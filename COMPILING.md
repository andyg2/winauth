# How to compile WinAuth

## Windows (Visual Studio)

### Prerequisites

* Visual Studio 2019

### Installation

1. Install Visual Studio 2019.
2. Git clone or download and extract the codebase.

### Building

1. Before starting, make sure to backup your `%AppData%\WinAuth\winauth.xml` file or export your authenticators to prevent data loss.
2. Open the solution file `WinAuth.sln` in Visual Studio.
3. Visual Studio > Build > Build Solution.
4. If successful, the executable location should be `bin\Debug\WinAuth.exe` in the solution directory.
