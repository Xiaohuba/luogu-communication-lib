# luogu-communication-lib

**This project is in development. API is subject to change, and implementation may be buggy. DO NOT USE IT IN SERIOUS SCENARIOS.**

A header-only library for testing communication tasks on platforms like luogu. In fact, it is suitable for any platform that does not ban syscalls like `fork`, `prctl` and `pipe`.

Currently it only directly supports IO-style communication. However it's easy to write a grader that supports function-style communication with this library.

## installation

Just copy paste `luogu-communication-lib.h` on the top of your grader!

## usage

Write your grader in a function (lambda expression is also ok).

You can call `Communication::SubProcess::safe_invoke()` to create a subprocess.

Given a subprocess `x`, you can write to `x.fout` (which can be read via stdin of `x`), and read from `x.fin` (which contains the staff `x` writes to its stdout).

You can call `x.guard()` to wait for `x` to exit normally. If it does not exit normally the grader will call `exit(EXIT_FAILURE)`.

All subprocesses that are not guarded will be automatically guarded before the grader exits.

## security

Each time a subprocess is invoked, it will run from the beginning, to avoid any attempt to store information in global variables.

Also, we use seccomp to filter dangerous syscalls. The policy is described in `sandbox.policy`, in kafel policy language.

## todo

- [ ] Protection against side channel attack (e.g. send information using system time)