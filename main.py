from sign_tool_worker import SignToolWorker

if __name__ == "__main__":
    worker = SignToolWorker()
    worker.verify("test/test_executable")
