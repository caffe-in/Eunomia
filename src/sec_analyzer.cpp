/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2022, 郑昱笙，濮雯旭，张典典（牛校牛子队）
 * All rights reserved.
 */

#include "eunomia/sec_analyzer.h"

#include <spdlog/spdlog.h>

#include "openai/nlohmann/json.hpp"
#include "openai/openai.hpp"

const static sec_rule_describe default_rules[] = {
  sec_rule_describe{
      .level = sec_rule_level::event,
      .type = sec_rule_type::syscall,
      .name = "Insert-BPF",
      .message = "BPF program loaded",
      .signature = "bpf",
  },
  sec_rule_describe{
      .level = sec_rule_level::event,
      .type = sec_rule_type::syscall,
      .name = "Anti-Debugging",
      .message = "Process uses anti-debugging technique to block debugger",
      .signature = "ptrace",
  },
};

sec_analyzer_prometheus::sec_analyzer_prometheus(prometheus_server &server, const std::vector<sec_rule_describe> &in_rules)
    : sec_analyzer(in_rules),
      eunomia_sec_warn_counter(prometheus::BuildCounter()
                                   .Name("eunomia_seccurity_warn_count")
                                   .Help("Number of observed security warnings")
                                   .Register(*server.registry)),
      eunomia_sec_event_counter(prometheus::BuildCounter()
                                    .Name("eunomia_seccurity_event_count")
                                    .Help("Number of observed security event")
                                    .Register(*server.registry)),
      eunomia_sec_alert_counter(prometheus::BuildCounter()
                                    .Name("eunomia_seccurity_alert_count")
                                    .Help("Number of observed security alert")
                                    .Register(*server.registry))
{
}

std::string sec_rule_level_string(sec_rule_level level)
{
  switch (level)
  {
    case sec_rule_level::warnning: return "warnning";
    case sec_rule_level::event: return "event";
    case sec_rule_level::alert: return "alert";
    default: return "unknown";
  }
}

void sec_analyzer::print_event(const rule_message &msg)
{
  spdlog::info("{}", "Security Rule Detection:");
  spdlog::info("level: {}", sec_rule_level_string(msg.level));
  spdlog::info("name: {}", msg.name);
  spdlog::info("message: {}", msg.message);
  spdlog::info("pid: {}", msg.pid);
  spdlog::info("container_id: {}", msg.container_id);
  spdlog::info("container_name: {}", msg.container_name);
}

void sec_analyzer::report_event(const rule_message &msg)
{
  print_event(msg);
}

void sec_analyzer_prometheus::report_event(const rule_message &msg)
{
  print_event(msg);
  report_prometheus_event(msg);
}

void sec_analyzer_prometheus::report_prometheus_event(const struct rule_message &msg)
{
  switch (msg.level)
  {
    case sec_rule_level::event:
      eunomia_sec_event_counter
          .Add({ { "level", "event" },
                 { "name", msg.name },
                 { "message", msg.message },
                 { "pid", std::to_string(msg.pid) },
                 { "container_id", msg.container_id },
                 { "container_name", msg.container_name } })
          .Increment();
      break;
    case sec_rule_level::warnning:
      eunomia_sec_warn_counter
          .Add({ { "level", "warning" },
                 { "name", msg.name },
                 { "message", msg.message },
                 { "pid", std::to_string(msg.pid) },
                 { "container_id", msg.container_id },
                 { "container_name", msg.container_name } })
          .Increment();
      break;
    case sec_rule_level::alert:
      eunomia_sec_alert_counter
          .Add({ { "level", "alert" },
                 { "name", msg.name },
                 { "message", msg.message },
                 { "pid", std::to_string(msg.pid) },
                 { "container_id", msg.container_id },
                 { "container_name", msg.container_name } })
          .Increment();
      break;
    default: break;
  }
}

int syscall_rule_checker::check_rule(const tracker_event<syscall_event> &e, rule_message &msg)
{
  if (!analyzer)
  {
    return -1;
  }
  if (e.data.pid == getpid())
  {
    return -1;
  }
  for (std::size_t i = 0; i < analyzer->rules.size(); i++)
  {
    if (analyzer->rules[i].type == sec_rule_type::syscall &&
        analyzer->rules[i].signature == syscall_names_x86_64[e.data.syscall_id])
    {
      msg.level = analyzer->rules[i].level;
      msg.name = analyzer->rules[i].name;
      msg.message = analyzer->rules[i].message + ": " + e.data.comm;
      msg.pid = e.data.pid;
      // EVNETODO: fix get container id
      msg.container_id = "36fca8c5eec1";
      msg.container_name = "Ubuntu";
      return (int)i;
    }
  }
  return -1;
}

// llm rule check impletation by caffein

json syscall_llm_rule_checker::buildDataToSend(const std::vector<tracker_event<syscall_event>> &event_buffer)
{
  nlohmann::json j;
  std::string combined_prompts;
  j["model"] = "gpt-3.5-turbo";
  for (const auto &e : event_buffer)
  {
    combined_prompts += std::string(syscall_names_x86_64[e.data.syscall_id]) + " ";
    // std::cout << combined_prompts << std::endl;
    // "Evaluate syscall : " + std::string(syscall_names_x86_64[e.data.syscall_id]) + "\n";
  }
  j["prompt"] = combined_prompts;
  j["max_tokens"] = 100;
  j["temperature"] = 0;
  j["messages"] = nlohmann::json::array(
      { { { "role", "system" }, { "content", "Check syscall operation, if the operation may be dangerous, please tell me which is dangerous" } } });
  return j;
}
std::string syscall_llm_rule_checker::sendDataToLLM(const json &data)
{
  try
  {
    openai::start();  // 确保OpenAI库初始化

    auto completion = openai::completion().create(data);
    return completion.dump(2);  // 返回格式化的JSON响应
  }
  catch (const std::exception &e)
  {
    std::cerr << "Exception occurred: " << e.what() << '\n';
    return "";
  }
}

std::string syscall_llm_rule_checker::parseLLMResponse(const std::string &response)
{
  try
  {
    auto json_response = nlohmann::json::parse(response);
    std::string content = json_response["choices"][0]["message"]["content"];
    return content;
  }
  catch (const std::exception &e)
  {
    std::cerr << "Failed to parse LLM response: " << e.what() << std::endl;
    return "";
  }
}

int syscall_llm_rule_checker::check_rule(const tracker_event<syscall_event> &e, rule_message &msg)
{
  {
    std::lock_guard<std::mutex> lock(buffer_mutex);
    event_buffer.push_back(e);  // 将事件添加到缓冲区
    if (event_buffer.size() >= buffer_limit)
    {
      cond_var.notify_one();  // 如果达到了缓冲区大小限制，通知flushBuffer处理
    }
  }
  std::string response_copy;
  {
    std::lock_guard<std::mutex> lock(response_mutex);
    response_copy = last_response;  // 安全地获取最新的响应
  }

  if (!response_copy.empty())
  {
    msg.message = response_copy;  // 将获取的响应赋值给msg
    std::cout << "Updated response is available." << std::endl;
    return 0;  // 成功
  }
  else
  {
    // std::cout << "No updated response available yet." << std::endl;
    return -1;  // 表示没有更新的数据
  }
}

json process_llm_rule_checker::buildDataToSend(const std::vector<tracker_event<process_event>> &event_buffer)
{
  nlohmann::json j;
  std::string combined_prompts;
  j["model"] = "gpt-3.5-turbo";
  for (const auto &e : event_buffer)
  {
    combined_prompts += std::string("the comm:") + e.data.comm + "," + "the file name:" + e.data.filename + "\n";
    // std::cout << combined_prompts << std::endl;
    // "Evaluate syscall : " + std::string(syscall_names_x86_64[e.data.syscall_id]) + "\n";
  }
  j["prompt"] = combined_prompts;
  j["max_tokens"] = 100;
  j["temperature"] = 0;
  j["messages"] = nlohmann::json::array(
      { { { "role", "system" }, { "content", "Check process operation, if the operation may be dangerous, please tell me which is dangerous" } } });
  return j;
}
std::string process_llm_rule_checker::sendDataToLLM(const json &data)
{
  try
  {
    openai::start();  // 确保OpenAI库初始化

    auto completion = openai::completion().create(data);
    return completion.dump(2);  // 返回格式化的JSON响应
  }
  catch (const std::exception &e)
  {
    std::cerr << "Exception occurred: " << e.what() << '\n';
    return "";
  }
}

std::string process_llm_rule_checker::parseLLMResponse(const std::string &response)
{
  try
  {
    auto json_response = nlohmann::json::parse(response);
    std::string content = json_response["choices"][0]["message"]["content"];
    return content;
  }
  catch (const std::exception &e)
  {
    std::cerr << "Failed to parse LLM response: " << e.what() << std::endl;
    return "";
  }
}

int process_llm_rule_checker::check_rule(const tracker_event<process_event> &e, rule_message &msg)
{
  {
    std::lock_guard<std::mutex> lock(buffer_mutex);
    event_buffer.push_back(e);  // 将事件添加到缓冲区
    if (event_buffer.size() >= buffer_limit)
    {
      cond_var.notify_one();  // 如果达到了缓冲区大小限制，通知flushBuffer处理
    }
  }
  std::string response_copy;
  {
    std::lock_guard<std::mutex> lock(response_mutex);
    response_copy = last_response;  // 安全地获取最新的响应
  }

  if (!response_copy.empty())
  {
    msg.message = response_copy;  // 将获取的响应赋值给msg
    std::cout << "Updated response is available." << std::endl;
    return 0;  // 成功
  }
  else
  {
    // std::cout << "No updated response available yet." << std::endl;
    return -1;  // 表示没有更新的数据
  }
}

json files_llm_rule_checker::buildDataToSend(const std::vector<tracker_event<files_event>> &event_buffer)
{
  nlohmann::json j;
  std::string combined_prompts;
  j["model"] = "gpt-3.5-turbo";
  for (const auto &e : event_buffer)
  {
    std::stringstream ss;
    ss << "pid: " << e.data.pid << ", rows: " << e.data.rows << ", values: ";
    for (size_t i = 0; i < e.data.rows; i++)
    {
      ss << "file name: " << e.data.values[i].filename << ", read: " << e.data.values[i].read_bytes
         << ", write: " << e.data.values[i].write_bytes << "; ";
    }
    combined_prompts += ss.str()+"\n";
    // std::cout << combined_prompts << std::endl;
    // "Evaluate syscall : " + std::string(syscall_names_x86_64[e.data.syscall_id]) + "\n";
  }
      std::cout << combined_prompts << std::endl;
  j["prompt"] = combined_prompts;
  j["max_tokens"] = 100;
  j["temperature"] = 0;
  j["messages"] = nlohmann::json::array(
      { { { "role", "system" }, { "content", "Check file operation, if the operation may be dangerous, please tell me which is dangerous" } } });
  return j;
}
std::string files_llm_rule_checker::sendDataToLLM(const json &data)
{
  try
  {
    openai::start();  // 确保OpenAI库初始化

    auto completion = openai::completion().create(data);
    return completion.dump(2);  // 返回格式化的JSON响应
  }
  catch (const std::exception &e)
  {
    std::cerr << "Exception occurred: " << e.what() << '\n';
    return "";
  }
}

std::string files_llm_rule_checker::parseLLMResponse(const std::string &response)
{
  try
  {
    auto json_response = nlohmann::json::parse(response);
    std::string content = json_response["choices"][0]["message"]["content"];
    return content;
  }
  catch (const std::exception &e)
  {
    std::cerr << "Failed to parse LLM response: " << e.what() << std::endl;
    return "";
  }
}

int files_llm_rule_checker::check_rule(const tracker_event<files_event> &e, rule_message &msg)
{
  {
    std::lock_guard<std::mutex> lock(buffer_mutex);
    event_buffer.push_back(e);  // 将事件添加到缓冲区
    if (event_buffer.size() >= buffer_limit)
    {
      cond_var.notify_one();  // 如果达到了缓冲区大小限制，通知flushBuffer处理
    }
  }
  std::string response_copy;
  {
    std::lock_guard<std::mutex> lock(response_mutex);
    response_copy = last_response;  // 安全地获取最新的响应
  }

  if (!response_copy.empty())
  {
    msg.message = response_copy;  // 将获取的响应赋值给msg
    std::cout << "Updated response is available." << std::endl;
    return 0;  // 成功
  }
  else
  {
    // std::cout << "No updated response available yet." << std::endl;
    return -1;  // 表示没有更新的数据
  }
}
/*

examples:

[bpf_rule]
type = "syscall"
name = "Insert-BPF"
syscall = "bpf"
error_message = "BPF program loaded"

[debug]
type = "syscall"
name = "Anti-Debugging"
error_message = "Process uses anti-debugging technique to block debugger"
*/

std::shared_ptr<sec_analyzer> sec_analyzer::create_sec_analyzer_with_default_rules(void)
{
  return create_sec_analyzer_with_additional_rules(std::vector<sec_rule_describe>());
}

std::shared_ptr<sec_analyzer> sec_analyzer::create_sec_analyzer_with_additional_rules(
    const std::vector<sec_rule_describe> &rules)
{
  std::vector<sec_rule_describe> all_rules;
  for (auto &rule : default_rules)
  {
    all_rules.push_back(rule);
  }
  all_rules.insert(all_rules.end(), rules.begin(), rules.end());
  return std::make_shared<sec_analyzer>(all_rules);
}

std::shared_ptr<sec_analyzer> sec_analyzer_prometheus::create_sec_analyzer_with_default_rules(prometheus_server &server)
{
  return create_sec_analyzer_with_additional_rules(std::vector<sec_rule_describe>(), server);
}

std::shared_ptr<sec_analyzer> sec_analyzer_prometheus::create_sec_analyzer_with_additional_rules(
    const std::vector<sec_rule_describe> &rules,
    prometheus_server &server)
{
  std::vector<sec_rule_describe> all_rules;
  for (auto &rule : default_rules)
  {
    all_rules.push_back(rule);
  }
  all_rules.insert(all_rules.end(), rules.begin(), rules.end());
  return std::make_shared<sec_analyzer_prometheus>(server, all_rules);
}
