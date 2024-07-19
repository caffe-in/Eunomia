#ifndef EVENTS_WRAPPER_H
#define EVENTS_WRAPPER_H

#include <string>
#include <nlohmann/json.hpp>
#include "../bpftools/syscall/syscall.h"
#include "../bpftools/process/process.h"
#include "../bpftools/files/file_tracker.h"
#include "include/eunomia/syscall_helper.h"
using json = nlohmann::json;

class event_base {
public:
    virtual ~event_base() = default;
    virtual std::string buildDataToSend() const = 0;
};

class syscall_event_wrapper : public event_base {
private:
    syscall_event event;

public:
    syscall_event_wrapper(const syscall_event& ev) : event(ev) {}
    
    std::string buildDataToSend() const override {
        return std::string(syscall_names_x86_64[event.syscall_id]);
    }
};

// process_event 的包装类
class process_event_wrapper : public event_base {
private:
    process_event event;

public:
    process_event_wrapper(const process_event& ev) : event(ev) {}

    std::string buildDataToSend() const override {
        return std::string("the comm:"+event.comm+","+"the file name:"+event.filename);
    }
};

class files_event_wrapper : public event_base {
private:
    files_event event;

public:
    files_event_wrapper(const files_event& ev) : event(ev) {}

    std::string buildDataToSend() const override {
        json files_json = json::array(); // 创建一个JSON数组存储所有文件信息
        for (size_t i = 0; i < event.rows; ++i) {
            files_json.push_back({
                {"filename", std::string(event.values[i].filename)},
                {"size", event.values[i].size}
            });
        }

        return {
            {"pid", event.pid},
            {"files", files_json}
        };
    }
};
#endif // EVENTS_WRAPPER_H