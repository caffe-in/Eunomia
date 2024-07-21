#ifndef EVENTS_WRAPPER_H
#define EVENTS_WRAPPER_H

#include <sstream>
#include <string>

#include "../bpftools/files/file_tracker.h"
#include "syscall_helper.h"
using json = nlohmann::json;

class event_base {
public:
    virtual ~event_base() = default;
    virtual std::string buildDataToSend() const = 0;
    virtual std::string buildDataToSend() const = 0;
};

class syscall_event_wrapper : public event_base
{
 private:
  syscall_event event;

public:
    syscall_event_wrapper(const syscall_event& ev) : event(ev) {}
    
    std::string buildDataToSend() const override {
        return std::string(syscall_names_x86_64[event.syscall_id]);
    std::string buildDataToSend() const override {
        return std::string(syscall_names_x86_64[event.syscall_id]);
    }
};

// process_event 的包装类
class process_event_wrapper : public event_base
{
 private:
  process_event event;

 public:
  process_event_wrapper(const process_event& ev) : event(ev)
  {
  }

    std::string buildDataToSend() const override {

        return std::string("the comm:")+event.comm+","+"the file name:"+event.filename+"\n";
    }
};

class file_event_wrapper:public event_base
{
private:
  files_event event;
public:
    file_event_wrapper(const files_event& ev) : event(ev)
    {
    }
    
        std::string buildDataToSend() const override {
            std::stringstream ss;
            ss << "pid: " << event.pid << ", rows: " << event.rows << ", values: ";
            for (size_t i = 0; i < event.rows; i++) {
                ss << "file name: " << event.values[i].filename << ", read: " << event.values[i].read_bytes << ", write: " << event.values[i].write_bytes << "; ";
            }
            return ss.str();
        }
    };
#endif  // EVENTS_WRAPPER_H