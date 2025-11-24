from monitor.auth_monitor import AuthMonitor

if __name__ == "__main__":
    mon = AuthMonitor()

    while True:
        print("\n--- LOGIN SIMULATION ---")
        u = input("Username: ")
        p = input("Password: ")
        ip = "127.0.0.1"

        ok = mon.check_login(u, p, ip)

        if ok:
            print("LOGIN SUCCESS")
        else:
            print("LOGIN FAILED")

