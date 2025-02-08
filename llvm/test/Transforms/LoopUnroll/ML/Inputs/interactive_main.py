import interactive_host
import sys


def main(args):
    class Advisor:
        to_return = False

        def advice(self, _):
            l = [0.5 for _ in range(32 - 2)]
            l[int(args[0])] = float(args[1])
            return l

        def read_before_advice(self, fc):
            json = fc.readline()
            print(json)
            heuristic = int.from_bytes(fc.read(8))
            print(heuristic)
            fc.readline()

        def read_after_advice(self, fc):
            json = fc.readline()
            print(json)
            action = bool(int.from_bytes(fc.read(1)))
            print(action)
            fc.readline()


    a = Advisor()
    interactive_host.run_interactive(args[2],
                                     a.advice,
                                     args[3:],
                                     a.read_before_advice,
                                     a.read_after_advice)


if __name__ == "__main__":
    main(sys.argv[1:])
