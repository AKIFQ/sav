"""Policy management for Shadow VCS."""
import ast
import fnmatch
from pathlib import Path
from typing import Any, Optional

from ruamel.yaml import YAML


class PolicyRule:
    """Represents a single policy rule."""

    def __init__(self, rule_dict: dict):
        """Initialize from rule dictionary."""
        self.match = rule_dict.get("match", "*")
        self.auto_approve = rule_dict.get("auto_approve", False)
        self.require_role = rule_dict.get("require_role")
        self.condition = rule_dict.get("condition")
        
        # Validate rule
        if self.require_role and self.auto_approve:
            raise ValueError("Rule cannot have both auto_approve and require_role")
        
        if self.condition:
            # Validate condition is safe
            self._validate_condition(self.condition)

    def _validate_condition(self, condition: str):
        """Validate that a condition expression is safe."""
        # Parse the condition
        try:
            tree = ast.parse(condition, mode="eval")
        except SyntaxError as e:
            raise ValueError(f"Invalid condition syntax: {e}")
        
        # Check for allowed operations only
        allowed_names = {"risk_score", "lines_added", "lines_deleted"}
        allowed_node_types = {
            ast.Expression, ast.Compare, ast.BoolOp, ast.BinOp,
            ast.UnaryOp, ast.Name, ast.Constant, ast.Load,
            ast.Lt, ast.LtE, ast.Gt, ast.GtE, ast.Eq, ast.NotEq,
            ast.And, ast.Or, ast.Not, ast.Add, ast.Sub, ast.Mult,
            ast.Div, ast.Mod
        }
        
        for node in ast.walk(tree):
            # Check node types
            if type(node) not in allowed_node_types:
                raise ValueError(f"Unsafe operation in condition: {type(node).__name__}")
            
            # Check variable names
            if isinstance(node, ast.Name) and node.id not in allowed_names:
                raise ValueError(f"Unknown variable in condition: {node.id}")

    def matches_file(self, file_path: str) -> bool:
        """Check if this rule matches a file path."""
        return fnmatch.fnmatch(file_path, self.match)

    def evaluate_condition(self, context: dict) -> bool:
        """Evaluate the condition with given context."""
        if not self.condition:
            return True
        
        # Create safe evaluation context
        safe_context = {
            "risk_score": context.get("risk_score", 0),
            "lines_added": context.get("lines_added", 0),
            "lines_deleted": context.get("lines_deleted", 0),
        }
        
        try:
            return eval(self.condition, {"__builtins__": {}}, safe_context)
        except Exception:
            # If evaluation fails, be conservative
            return False


class PolicyManager:
    """Manages policy rules for Shadow VCS."""

    def __init__(self, repo):
        """Initialize policy manager with repository."""
        self.repo = repo
        self.constraints_path = self.repo.zed_dir / "constraints.yaml"
        self.rules: list[PolicyRule] = []
        self._load_rules()

    def _load_rules(self):
        """Load rules from constraints.yaml."""
        if not self.constraints_path.exists():
            # No constraints file, use empty rules
            self.rules = []
            return
        
        yaml = YAML()
        yaml.preserve_quotes = True
        
        with open(self.constraints_path, "r") as f:
            data = yaml.load(f)
        
        if not data or "rules" not in data:
            self.rules = []
            return
        
        # Load each rule
        self.rules = []
        for rule_dict in data["rules"]:
            try:
                rule = PolicyRule(rule_dict)
                self.rules.append(rule)
            except ValueError as e:
                # Skip invalid rules
                print(f"Warning: Skipping invalid rule: {e}")

    def evaluate(self, fingerprint, files: list[Path]) -> dict:
        """Evaluate policy rules against a commit fingerprint.
        
        Returns:
            Dictionary with:
            - approved: bool (whether commit is auto-approved)
            - require_role: Optional[str] (required role if any)
            - matched_rule: Optional[int] (index of matched rule)
        """
        context = {
            "risk_score": fingerprint.risk_score,
            "lines_added": fingerprint.lines_added,
            "lines_deleted": fingerprint.lines_deleted,
        }
        
        # Check each rule in order
        for i, rule in enumerate(self.rules):
            # Check if rule matches any file
            matches_any = False
            for file_path in files:
                if rule.matches_file(str(file_path)):
                    matches_any = True
                    break
            
            if not matches_any:
                continue
            
            # Evaluate condition
            if not rule.evaluate_condition(context):
                continue
            
            # Rule matches - return result
            return {
                "approved": rule.auto_approve,
                "require_role": rule.require_role,
                "matched_rule": i,
            }
        
        # No rule matched - default to not approved
        return {
            "approved": False,
            "require_role": None,
            "matched_rule": None,
        }

    def reload(self):
        """Reload rules from constraints file."""
        self._load_rules()

    def test_rule(self, rule_dict: dict, test_context: dict) -> bool:
        """Test a single rule with given context."""
        try:
            rule = PolicyRule(rule_dict)
            return rule.evaluate_condition(test_context)
        except Exception as e:
            raise ValueError(f"Rule test failed: {e}") 