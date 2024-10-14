from cx_Freeze import setup, Executable

# Define the executable configuration
executables = [Executable("src/main.py", base=None)]

# Setup configuration
setup(
    name = "Whois Service",
    version = "1.1",
    description = "A service to check registry for domains",
    executables = executables,
    options={
        'build_exe': {
            'packages': [],
            'excludes': [],
            'include_files': [],
        }
    }
)
