import os
import json
import ast

def analyze_file(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        source = f.read()
    try:
        tree = ast.parse(source, filename=filepath)
    except SyntaxError:
        return None
    result = {
        "missing_type_hints": [],
        "missing_docstrings": [],
        "long_functions": [],
        "duplicate_imports": [],
        "broad_excepts": []
    }
    # Imports tracking
    import_counts = {}
    import_lines = {}
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    name = alias.name
                    import_counts.setdefault(name, 0)
                    import_counts[name] += 1
                    import_lines.setdefault(name, []).append(node.lineno)
            else:  # ImportFrom
                module = node.module or ""
                import_counts.setdefault(module, 0)
                import_counts[module] += 1
                import_lines.setdefault(module, []).append(node.lineno)
    for name, cnt in import_counts.items():
        if cnt > 1:
            # report all but the first occurrence
            result["duplicate_imports"].extend(import_lines[name][1:])

    # Function analysis
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # Length
            if hasattr(node, 'end_lineno'):
                length = node.end_lineno - node.lineno + 1
            else:
                # fallback: estimate by counting lines in source slice
                length = len(source.splitlines()[node.lineno-1:node.lineno+39])
            if length > 40:
                result["long_functions"].append({"start": node.lineno, "end": getattr(node, 'end_lineno', node.lineno+length-1)})
            # Docstring
            if ast.get_docstring(node) is None:
                result["missing_docstrings"].append(node.lineno)
            # Type hints
            missing_hint = False
            for arg in node.args.args:
                if arg.annotation is None:
                    missing_hint = True
                    break
            # varargs, kwonlyargs, kwarg
            for arg in getattr(node.args, 'kwonlyargs', []):
                if arg.annotation is None:
                    missing_hint = True
                    break
            for arg in getattr(node.args, 'posonlyargs', []):
                if arg.annotation is None:
                    missing_hint = True
                    break
            if node.args.vararg and getattr(node.args.vararg, 'annotation', None) is None:
                missing_hint = True
            if node.args.kwarg and getattr(node.args.kwarg, 'annotation', None) is None:
                missing_hint = True
            # Return
            if node.returns is None:
                missing_hint = True
            if missing_hint:
                result["missing_type_hints"].append(node.lineno)
        # Broad except
        if isinstance(node, ast.Try):
            for handler in node.handlers:
                if handler.type is None:
                    result["broad_excepts"].append(handler.lineno)
                elif isinstance(handler.type, ast.Name) and handler.type.id == 'Exception':
                    result["broad_excepts"].append(handler.lineno)
    return result

def main():
    root = os.path.abspath(os.path.dirname(__file__))
    audit = {}
    for dirpath, dirnames, filenames in os.walk(root):
        # skip __pycache__ and hidden dirs
        if '__pycache__' in dirpath:
            continue
        for fname in filenames:
            if fname.endswith('.py') and fname != os.path.basename(__file__):
                fpath = os.path.join(dirpath, fname)
                analysis = analyze_file(fpath)
                if analysis is not None:
                    rel = os.path.relpath(fpath, root)
                    audit[rel] = analysis
    print(json.dumps(audit, indent=2))

if __name__ == '__main__':
    main()
