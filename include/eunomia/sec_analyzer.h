/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2022, 郑昱笙，濮雯旭，张典典（牛校牛子队）
 * All rights reserved.
 */

#ifndef EUNOMIA_SEC_ANALYZER_H
#define EUNOMIA_SEC_ANALYZER_H

#include <curl/curl.h>

#include <chrono>
#include <condition_variable>
#include <json.hpp>
#include <mutex>
#include <thread>
#include <vector>

#include "files.h"
#include "model/event_handler.h"
#include "process.h"
#include "prometheus_server.h"
#include "syscall.h"
#include <curl/curl.h>
#include <json.hpp>
#include <vector>
#include <mutex>
#include <chrono>
#include <thread>
#include <condition_variable>
#include "wrapper.h"
#include <vector>
#include <mutex>
#include <chrono>
#include <thread>
#include <condition_variable>
#include "wrapper.h"

using json = nlohmann::json;

/// sec rules info level
enum class sec_rule_level
{
  event,
  warnning,
  alert,
  // TODO: add more levels?
};

/// sec rules type

/// eg. system call, file access, etc.
enum class sec_rule_type
{
  syscall,
  tcp,
  process,
  files,
  mix,
  // TODO: add more types?
};

/// message for sec_rule

/// eg. read from file: xxx
struct rule_message
{
  sec_rule_level level;
  std::string name;
  std::string message;
  int pid;

  std::string container_id;
  std::string container_name;
};

/// describe a sec_rule
struct sec_rule_describe
{
  sec_rule_level level;
  sec_rule_type type;
  std::string name;
  std::string message;

  /// signature: the signature of the rule, for example, process name, syscall name, etc.
  std::string signature;
};

/// sec analyzer manager
class sec_analyzer
{
 public:
  // EVNETODO: use the mutex
  std::mutex mutex;
  const std::vector<sec_rule_describe> rules;

  sec_analyzer(const std::vector<sec_rule_describe> &in_rules) : rules(in_rules)
  {
  }
  virtual ~sec_analyzer() = default;
  virtual void report_event(const rule_message &msg);
  void print_event(const rule_message &msg);

  static std::shared_ptr<sec_analyzer> create_sec_analyzer_with_default_rules(void);
  static std::shared_ptr<sec_analyzer> create_sec_analyzer_with_additional_rules(
      const std::vector<sec_rule_describe> &rules);
};

/// sec analyzer manager with prometheus exporter
class sec_analyzer_prometheus : public sec_analyzer
{
 private:
  prometheus::Family<prometheus::Counter> &eunomia_sec_warn_counter;
  prometheus::Family<prometheus::Counter> &eunomia_sec_event_counter;
  prometheus::Family<prometheus::Counter> &eunomia_sec_alert_counter;

 public:
  void report_prometheus_event(const struct rule_message &msg);
  void report_event(const rule_message &msg);
  sec_analyzer_prometheus(prometheus_server &server, const std::vector<sec_rule_describe> &rules);

  static std::shared_ptr<sec_analyzer> create_sec_analyzer_with_default_rules(prometheus_server &server);
  static std::shared_ptr<sec_analyzer> create_sec_analyzer_with_additional_rules(
      const std::vector<sec_rule_describe> &rules,
      prometheus_server &server);
};

/// base class for securiy rules detect handler
template<typename EVNET>
class rule_base : public event_handler<EVNET>
{
 public:
  std::shared_ptr<sec_analyzer> analyzer;
  rule_base(std::shared_ptr<sec_analyzer> analyzer_ptr) : analyzer(analyzer_ptr)
  {
  }
  virtual ~rule_base() = default;

  // return rule id if matched
  // return -1 if not matched
  virtual int check_rule(const tracker_event<EVNET> &e, rule_message &msg) = 0;
  void handle(tracker_event<EVNET> &e)
  {
    if (!analyzer)
    {
      std::cout << "analyzer is null" << std::endl;
    }
    struct rule_message msg;
    int res = check_rule(e, msg);
    if (res != -1)
    {
      analyzer->report_event(msg);
    }
  }
};

/// files rule:

/// for example, a read or write to specific file
class files_rule_checker : public rule_base<files_event>
{
 public:
  virtual ~files_rule_checker() = default;
  files_rule_checker(std::shared_ptr<sec_analyzer> analyzer_ptr) : rule_base(analyzer_ptr)
  {
  }
  int check_rule(const tracker_event<files_event> &e, rule_message &msg);
};

/// process rule:

/// for example, a specific process is running
class process_rule_checker : public rule_base<process_event>
{
 public:
  virtual ~process_rule_checker() = default;
  process_rule_checker(std::shared_ptr<sec_analyzer> analyzer_ptr) : rule_base(analyzer_ptr)
  {
  }
  int check_rule(const tracker_event<process_event> &e, rule_message &msg);
};

/// syscall rule:

/// for example, a process is using a syscall
class syscall_rule_checker : public rule_base<syscall_event>
{
 public:
  syscall_rule_checker(std::shared_ptr<sec_analyzer> analyzer_ptr) : rule_base(analyzer_ptr)
  {
  }
  int check_rule(const tracker_event<syscall_event> &e, rule_message &msg);
};

/// llm rule:

// create by caffein for test, just using syscall event

class syscall_llm_rule_checker : public rule_base<syscall_event>
{
private:
    std::string llm_server_url;
    std::vector<tracker_event<syscall_event>> event_buffer;
    std::mutex buffer_mutex;
    std::mutex response_mutex;
    std::string last_response;
    std::condition_variable cond_var;
    const size_t buffer_limit = 100; // 可调整大小
    const std::chrono::seconds flush_interval = std::chrono::seconds(5); // 每5秒刷新一次
    std::thread flush_thread;
    bool stop_thread = false;

    json buildDataToSend(const std::vector<tracker_event<syscall_event>>& event_buffer);
    std::string sendDataToLLM(const json& data);
    static size_t writeCallback(void* contents, size_t size, size_t nmemb, void* userp);
    std::string parseLLMResponse(const std::string& response);

    void flush_buffer() {
        while (!stop_thread) {
            std::unique_lock<std::mutex> lock(buffer_mutex);
            cond_var.wait_for(lock, flush_interval, [this] { return event_buffer.size() >= buffer_limit || stop_thread; });
            if (event_buffer.empty()) continue;

            // 打包并发送数据到LLM
            json data = buildDataToSend(event_buffer);
            std::string response = sendDataToLLM(data);
            {
                std::lock_guard<std::mutex> resp_lock(response_mutex);
                last_response =parseLLMResponse(response); // 更新存储的响应
            }
            event_buffer.clear();
        }
    }
    
    std::string parseLLMResponse(const std::string& response);

    void flush_buffer() {
        while (!stop_thread) {
            std::unique_lock<std::mutex> lock(buffer_mutex);
            cond_var.wait_for(lock, flush_interval, [this] { return event_buffer.size() >= buffer_limit || stop_thread; });
            if (event_buffer.empty()) continue;

            // 打包并发送数据到LLM
            json data = buildDataToSend(event_buffer);
            std::string response = sendDataToLLM(data);
            {
                std::lock_guard<std::mutex> resp_lock(response_mutex);
                last_response =parseLLMResponse(response); // 更新存储的响应
            }
            event_buffer.clear();
        }
    }
    

public:
  virtual ~syscall_llm_rule_checker() {
    stop_thread = true;      // 设置停止标志
    cond_var.notify_all();   // 通知所有等待的线程
    if (flush_thread.joinable()) {
        flush_thread.join(); // 等待线程结束
    }}
    syscall_llm_rule_checker(std::shared_ptr<sec_analyzer> analyzer_ptr) : rule_base(analyzer_ptr), flush_thread(&syscall_llm_rule_checker::flush_buffer, this) {
        std::cout << "llm_rule_checker created" << std::endl;
    }
  int check_rule(const tracker_event<syscall_event>&e, rule_message &msg);
};

class process_llm_rule_checker : public rule_base<process_event>
{
private:
    std::string llm_server_url;
    std::vector<tracker_event<process_event>> event_buffer;
    std::mutex buffer_mutex;
    std::mutex response_mutex;
    std::string last_response;
    std::condition_variable cond_var;
    const size_t buffer_limit = 100; // 可调整大小
    const std::chrono::seconds flush_interval = std::chrono::seconds(5); // 每5秒刷新一次
    std::thread flush_thread;
    bool stop_thread = false;

    json buildDataToSend(const std::vector<tracker_event<process_event>>& event_buffer);
    std::string sendDataToLLM(const json& data);
    static size_t writeCallback(void* contents, size_t size, size_t nmemb, void* userp);
    std::string parseLLMResponse(const std::string& response);

    void flush_buffer() {
        while (!stop_thread) {
            std::unique_lock<std::mutex> lock(buffer_mutex);
            cond_var.wait_for(lock, flush_interval, [this] { return event_buffer.size() >= buffer_limit || stop_thread; });
            if (event_buffer.empty()) continue;

            // 打包并发送数据到LLM
            json data = buildDataToSend(event_buffer);
            std::string response = sendDataToLLM(data);
            {
                std::lock_guard<std::mutex> resp_lock(response_mutex);
                last_response =parseLLMResponse(response); // 更新存储的响应
            }
            event_buffer.clear();
        }
    }
    

public:
  virtual ~process_llm_rule_checker() {
    stop_thread = true;      // 设置停止标志
    cond_var.notify_all();   // 通知所有等待的线程
    if (flush_thread.joinable()) {
        flush_thread.join(); // 等待线程结束
    }}
    process_llm_rule_checker(std::shared_ptr<sec_analyzer> analyzer_ptr) : rule_base(analyzer_ptr), flush_thread(&process_llm_rule_checker::flush_buffer, this) {
        std::cout << "llm_rule_checker created" << std::endl;
    }
  int check_rule(const tracker_event<process_event>&e, rule_message &msg);
};
class files_llm_rule_checker : public rule_base<files_event>
{
private:
    std::string llm_server_url;
    std::vector<tracker_event<files_event>> event_buffer;
    std::mutex buffer_mutex;
    std::mutex response_mutex;
    std::string last_response;
    std::condition_variable cond_var;
    const size_t buffer_limit = 100; // 可调整大小
    const std::chrono::seconds flush_interval = std::chrono::seconds(5); // 每5秒刷新一次
    std::thread flush_thread;
    bool stop_thread = false;

    json buildDataToSend(const std::vector<tracker_event<files_event>>& event_buffer);
    std::string sendDataToLLM(const json& data);
    static size_t writeCallback(void* contents, size_t size, size_t nmemb, void* userp);
    std::string parseLLMResponse(const std::string& response);

    void flush_buffer() {
        while (!stop_thread) {
            std::unique_lock<std::mutex> lock(buffer_mutex);
            cond_var.wait_for(lock, flush_interval, [this] { return event_buffer.size() >= buffer_limit || stop_thread; });
            if (event_buffer.empty()) continue;

            // 打包并发送数据到LLM
            json data = buildDataToSend(event_buffer);
            std::string response = sendDataToLLM(data);
            {
                std::lock_guard<std::mutex> resp_lock(response_mutex);
                last_response =parseLLMResponse(response); // 更新存储的响应
            }
            event_buffer.clear();
        }
    }
    

public:
  virtual ~files_llm_rule_checker() {
    stop_thread = true;      // 设置停止标志
    cond_var.notify_all();   // 通知所有等待的线程
    if (flush_thread.joinable()) {
        flush_thread.join(); // 等待线程结束
    }}
    files_llm_rule_checker(std::shared_ptr<sec_analyzer> analyzer_ptr) : rule_base(analyzer_ptr), flush_thread(&files_llm_rule_checker::flush_buffer, this) {
        std::cout << "llm_rule_checker created" << std::endl;
    }
  int check_rule(const tracker_event<files_event>&e, rule_message &msg);
};
#endif