from pathlib import Path

CODE = '''def function_{n}():
    """Auto-generated function {n}"""
    pass

class Class{n}:
    """Auto-generated class {n}"""
    def method_1(self): pass
    def method_2(self): pass
    def method_3(self): pass
'''

# Generate 50 files of 5000 lines each = 250K lines
for i in range(50):
    content = '\n'.join([CODE.format(n=j) for j in range(500)])
    Path(f'generated/module_{i:03d}.py').parent.mkdir(parents=True, exist_ok=True)
    Path(f'generated/module_{i:03d}.py').write_text(content)
    print(f'Generated module_{i:03d}.py')

print('Done!')
