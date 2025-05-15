#include <cstring>
#include <experimental/filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <memory>
#include <set>
#include <string>
#include <tuple>
#include <utility>

#include <ext/stdio_filebuf.h>

#include <dirent.h>
#include <linux/filter.h>
#include <linux/limits.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

namespace {
namespace CommunicationLib {

void sanitize_fd() {
  DIR *dir = opendir("/proc/self/fd");
  if (!dir) {
    perror("opendir");
    exit(EXIT_FAILURE);
  }
  dirent *entry;
  while ((entry = readdir(dir)) != nullptr) {
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
      continue;
    int fd = atoi(entry->d_name);
    if (fd != STDIN_FILENO && fd != STDOUT_FILENO)
      close(fd);
  }
  closedir(dir);
}
void setupSeccomp() {
  sock_filter filter[] = {
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0xc000003eu, 1, 0),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
      BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 0x40u, 4, 0),
      BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 0x1du, 0, 11),
      BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 0x38u, 1, 0),
      BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 0x20u, 9, 8),
      BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 0x3au, 8, 7),
      BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 0x13fu, 3, 0),
      BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 0xf0u, 1, 0),
      BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 0x44u, 5, 4),
      BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 0xf6u, 4, 3),
      BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 0x1b3u, 1, 0),
      BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 0x140u, 2, 1),
      BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 0x1b4u, 1, 0),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | 0x1u),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
  };
  sock_fprog prog{sizeof(filter) / sizeof(filter[0]), filter};
  prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
  prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0);
}

struct SubProcess {
  static inline std::set<pid_t> pids;
  pid_t _pid;
  __gnu_cxx::stdio_filebuf<char> _buf1, _buf2;
  SubProcess(pid_t __pid, int __i_pipe_fd, int __o_pipe_fd)
      : _pid(__pid), _buf1(__i_pipe_fd, std::ios::in),
        _buf2(__o_pipe_fd, std::ios::out), fin(&_buf1), fout(&_buf2) {
    pids.emplace(__pid);
  }

  struct _FinalGuard {
    ~_FinalGuard() {
      for (pid_t pid : pids) {
        int _status;
        waitpid(pid, &_status, 0);
        if (!WIFEXITED(_status) || WEXITSTATUS(_status) != EXIT_SUCCESS)
          exit(EXIT_FAILURE);
      }
    }
  } static inline __finalGuard;

public:
  SubProcess() = delete;
  SubProcess(SubProcess &&x) = delete;
  SubProcess(const SubProcess &) = delete;
  std::istream fin;
  std::ostream fout;
  void guard() const {
    if (!pids.count(_pid))
      return;
    int _status;
    waitpid(_pid, &_status, 0);
    if (!WIFEXITED(_status) || WEXITSTATUS(_status) != EXIT_SUCCESS)
      exit(EXIT_FAILURE);
    pids.erase(_pid);
  }
  static std::unique_ptr<SubProcess> safe_invoke() {
    int i_pipe_fd[2], o_pipe_fd[2];
    if (pipe(i_pipe_fd) == -1)
      perror("pipe"), exit(EXIT_FAILURE);
    if (pipe(o_pipe_fd) == -1)
      perror("pipe"), exit(EXIT_FAILURE);
    pid_t pid = fork();
    if (!pid) {
      const char *newArgv[] = {"/proc/self/exe", NULL};
      const char *newEnvp[] = {"IS_CHILD_PROCESS=1", NULL};
      dup2(o_pipe_fd[0], STDIN_FILENO);
      dup2(i_pipe_fd[1], STDOUT_FILENO);
      close(o_pipe_fd[1]), close(i_pipe_fd[0]);
      setupSeccomp();
      execve("/proc/self/exe", (char **)newArgv, (char **)newEnvp);
      perror("execve"), exit(EXIT_FAILURE);
    } else {
      close(i_pipe_fd[1]), close(o_pipe_fd[0]);
      return std::make_unique<SubProcess>(pid, i_pipe_fd[0], o_pipe_fd[1]);
    }
  }
};

} // namespace CommunicationLib
} // namespace

#define COMMUNICATION_LIB_REGISTER_GRADER(grader)                              \
  namespace {                                                                  \
  struct _Manager {                                                            \
    _Manager() {                                                               \
      using namespace std::string_literals;                                    \
      bool flg = 0;                                                            \
      for (auto i = 0; environ[i] != NULL; i++)                                \
        flg |= environ[i] == "IS_CHILD_PROCESS=1"s;                            \
      if (!flg) {                                                              \
        CommunicationLib::sanitize_fd();                                       \
        grader();                                                              \
        exit(0);                                                               \
      }                                                                        \
    }                                                                          \
  } __manager;                                                                 \
  }
