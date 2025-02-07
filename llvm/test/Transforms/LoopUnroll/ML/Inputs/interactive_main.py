import interactive_host
import sys


def main(args):
    class Advisor:
        to_return = False

        def advice(self, _):
            l = [0.5 for _ in range(32 - 2)]
            l[int(args[0])] = float(args[1])
            return l

    a = Advisor()
    interactive_host.run_interactive(args[2], a.advice, args[3:])


if __name__ == "__main__":
    main(sys.argv[1:])
