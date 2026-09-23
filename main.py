"""CLI 入口"""

import argparse


def cmd_serve(args):
    from app.main import run
    run()


def cmd_help(args):
    print("Cloud IAM/PAM Least Privilege")
    print("")
    print("子命令: serve (启动 FastAPI on 端口 5039)")
    print("更多子命令待开发（参考 docs/PRD.md 第 3 章节 Prompt）")


def main():
    parser = argparse.ArgumentParser(description="Cloud IAM/PAM Least Privilege")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("serve", help="启动 FastAPI")
    sub.add_parser("help", help="Help")
    args = parser.parse_args()
    dispatch = {"serve": cmd_serve, "help": cmd_help}
    dispatch[getattr(args, "command", "help") or "help"](args)


if __name__ == "__main__":
    main()
