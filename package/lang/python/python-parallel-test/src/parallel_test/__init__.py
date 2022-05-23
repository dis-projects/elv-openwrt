# Copyright 2019-2021 RnD Center "ELVEES", JSC

import itertools
import subprocess
import sys
import threading
import time


class CmdThread(threading.Thread):
    def __init__(self, cmd, par, output, lock=None, stop_event=threading.Event()):
        threading.Thread.__init__(self)
        self.cmd_str = str(cmd)
        self.par_str = str(par)
        self.returncode = None
        self.output = output
        self.stop_event = stop_event
        self.lock = lock

    def print_lock(self, msg):
        if self.lock is None:
            print(msg)
            return

        self.lock.acquire()
        print(msg)
        self.lock.release()

    def run(self):
        full_cmd = f"{self.cmd_str} {self.par_str}"
        while not self.stop_event.is_set():
            self.print_lock(f'"{full_cmd}" started...')
            t_start = time.time()
            self.returncode = subprocess.call(
                full_cmd, shell=True, stdout=self.output, stderr=subprocess.STDOUT
            )
            self.print_lock(
                f'"{full_cmd}": {"TEST FAILED" if self.returncode else "TEST PASSED"} '
                f"({time.time()-t_start:.1f} s)"
            )
            if self.returncode:
                self.stop_event.set()


class CmdThreadDispatcher(object):
    def __init__(self, print_time, full_time, cmds, pars, output, show_progress=True):
        assert full_time > 0, "Full time can not be less than or equal to 0."
        assert print_time > 0, "Print time can not be less than or equal to 0."
        assert (
            full_time >= 10 * print_time
        ), "Print time must be a least 10 times less than full time."

        self.threads = []
        self.print_time = print_time
        self.full_time = full_time
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        for cmd, par in zip(cmds, pars):
            self.threads.append(CmdThread(cmd, par, output, self.lock, self.stop_event))
        self.show_progress = show_progress

    def run(self):
        spinner = itertools.cycle(["-", "/", "|", "\\"])

        for thread in self.threads:
            thread.start()

        while self.full_time > 0 and not self.stop_event.is_set():
            if self.show_progress:
                self.lock.acquire()
                sys.stdout.write(next(spinner))
                sys.stdout.flush()
                sys.stdout.write("\b")
                self.lock.release()
            time.sleep(self.print_time)
            self.full_time -= self.print_time

        self.stop_event.set()
        while len(threading.enumerate()) > 1:
            time.sleep(self.print_time)
            if self.show_progress:
                self.lock.acquire()
                sys.stdout.write(next(spinner))
                sys.stdout.flush()
                sys.stdout.write("\b")
                self.lock.release()

        fail = sum(bool(t.returncode) for t in self.threads)

        if fail > 0:
            print("TEST FAILED")
        else:
            print("TEST PASSED")

        return fail
