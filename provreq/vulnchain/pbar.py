import os
import sys
import time


class ProgressBar:
    def __init__(self, msg, n_total):
        try:
            _, self.columns = os.popen("stty size", "r").read().split()
        except ValueError:
            _, self.columns = (24, 80)  # noqa
        self.space_counter = len(str(n_total)) + 2
        self.msg = msg
        print(msg)
        self.n_total = int(n_total)
        self.create_time = time.time()
        self.barlen = int(self.columns) - self.space_counter - 14
        self.d = n_total / self.barlen

    def done(self, msg=None):
        if msg:
            self.msg = msg
        else:
            self.msg = "Done"
        sys.stdout.write(("\r{:%s}" % self.columns).format(self.msg))
        print()

    def update(self, curr):
        if curr == 0:
            curr = 1
        c = int(curr / self.d)
        now = time.time()
        pr_element = (now - self.create_time) / float(curr)
        # p = curr / tot * 100

        p = int(pr_element * (self.n_total - curr))

        if p > 60 * 60:
            time_msg = "{:3.0f}h".format((p / (60 * 60)))
        elif p > 60:
            time_msg = "{:3.0f}m".format((p / 60))
        else:
            time_msg = "{:3.0f}s".format(p)

        sys.stdout.write(
            ("\r{:%s} [ {:%s} ] {}" % (self.space_counter, self.barlen)).format(
                curr, c * "#", time_msg
            )
        )
