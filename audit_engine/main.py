import argparse
import json

from engine import run_audit


def get_arguments():

    parser = argparse.ArgumentParser()

    parser.add_argument("target")

    return parser.parse_args()


def main():

    args = get_arguments()

    report = run_audit(args.target)

    print(
        json.dumps(
            report,
            indent=4
        )
    )


if __name__ == "__main__":

    main()