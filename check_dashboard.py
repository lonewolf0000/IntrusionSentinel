import py_compile

try:
    py_compile.compile('dashboard.py')
    print("Compilation successful - no syntax errors found")
except py_compile.PyCompileError as e:
    print(f"Compilation error: {e}")
except Exception as e:
    print(f"Error: {e}") 