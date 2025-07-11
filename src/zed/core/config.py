"""Configuration management for Shadow VCS."""
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Dict, Any
import json

from ruamel.yaml import YAML


@dataclass
class DatabaseConfig:
    """Database configuration settings."""
    timeout_seconds: int = 30
    cache_size_mb: int = 10
    wal_mode: bool = True
    optimize_on_connect: bool = True
    bulk_insert_batch_size: int = 1000


@dataclass
class SecurityConfig:
    """Security configuration settings."""
    max_file_size_mb: int = 10
    allow_binary_files: bool = True
    enable_path_validation: bool = True
    auto_apply_enabled: bool = True
    auto_apply_risk_threshold: float = 0.1
    auto_apply_max_lines: int = 10
    auto_apply_file_patterns: list = field(default_factory=lambda: ["*.md", "*.txt", "*.rst"])


@dataclass
class PerformanceConfig:
    """Performance configuration settings."""
    fingerprint_cache_size: int = 128
    metrics_retention_days: int = 90
    audit_log_retention_days: int = 365
    concurrent_operations: int = 4
    test_timeout_seconds: int = 300


@dataclass
class MonitoringConfig:
    """Monitoring configuration settings."""
    health_check_enabled: bool = True
    metrics_collection_enabled: bool = True
    disk_space_warning_mb: int = 100
    stale_commit_warning_days: int = 30
    performance_tracking_enabled: bool = True


@dataclass
class ShadowVCSConfig:
    """Complete Shadow VCS configuration."""
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    performance: PerformanceConfig = field(default_factory=PerformanceConfig)
    monitoring: MonitoringConfig = field(default_factory=MonitoringConfig)
    
    # Global settings
    log_level: str = "INFO"
    debug_mode: bool = False
    config_file_path: Optional[Path] = None


class ConfigManager:
    """Manages Shadow VCS configuration from multiple sources."""
    
    def __init__(self, repo_path: Optional[Path] = None):
        """Initialize configuration manager."""
        self.repo_path = repo_path
        self._config = ShadowVCSConfig()
        self._load_configuration()
    
    def _load_configuration(self):
        """Load configuration from multiple sources in order of precedence."""
        # 1. Start with defaults (already set in dataclass)
        
        # 2. Load from global config file
        global_config = self._get_global_config_path()
        if global_config and global_config.exists():
            self._load_from_file(global_config)
        
        # 3. Load from repo-specific config file
        if self.repo_path:
            repo_config = self.repo_path / ".zed" / "config.yaml"
            if repo_config.exists():
                self._load_from_file(repo_config)
        
        # 4. Override with environment variables (highest precedence)
        self._load_from_environment()
    
    def _get_global_config_path(self) -> Optional[Path]:
        """Get path to global configuration file."""
        # Check common locations
        candidates = [
            Path.home() / ".zed" / "config.yaml",
            Path.home() / ".config" / "zed" / "config.yaml",
            Path("/etc/zed/config.yaml"),
        ]
        
        # Check ZED_CONFIG_PATH environment variable
        env_path = os.getenv("ZED_CONFIG_PATH")
        if env_path:
            candidates.insert(0, Path(env_path))
        
        for path in candidates:
            if path.exists():
                return path
        
        return None
    
    def _load_from_file(self, config_path: Path):
        """Load configuration from YAML file."""
        try:
            yaml = YAML(typ='safe')
            with open(config_path, 'r') as f:
                data = yaml.load(f) or {}
            
            self._apply_config_dict(data)
            self._config.config_file_path = config_path
            
        except Exception as e:
            # Non-fatal error - use defaults
            print(f"Warning: Could not load config from {config_path}: {e}")
    
    def _load_from_environment(self):
        """Load configuration from environment variables."""
        # Global settings
        if os.getenv("ZED_LOG_LEVEL"):
            self._config.log_level = os.getenv("ZED_LOG_LEVEL").upper()
        
        if os.getenv("ZED_DEBUG"):
            self._config.debug_mode = os.getenv("ZED_DEBUG").lower() in ("true", "1", "yes")
        
        # Database settings
        if os.getenv("ZED_DB_TIMEOUT"):
            try:
                self._config.database.timeout_seconds = int(os.getenv("ZED_DB_TIMEOUT"))
            except ValueError:
                pass
        
        if os.getenv("ZED_DB_CACHE_SIZE_MB"):
            try:
                self._config.database.cache_size_mb = int(os.getenv("ZED_DB_CACHE_SIZE_MB"))
            except ValueError:
                pass
        
        # Security settings
        if os.getenv("ZED_MAX_FILE_SIZE_MB"):
            try:
                self._config.security.max_file_size_mb = int(os.getenv("ZED_MAX_FILE_SIZE_MB"))
            except ValueError:
                pass
        
        if os.getenv("ZED_AUTO_APPLY"):
            self._config.security.auto_apply_enabled = os.getenv("ZED_AUTO_APPLY").lower() in ("true", "1", "yes")
        
        if os.getenv("ZED_AUTO_APPLY_RISK_THRESHOLD"):
            try:
                self._config.security.auto_apply_risk_threshold = float(os.getenv("ZED_AUTO_APPLY_RISK_THRESHOLD"))
            except ValueError:
                pass
        
        # Performance settings
        if os.getenv("ZED_TEST_TIMEOUT"):
            try:
                self._config.performance.test_timeout_seconds = int(os.getenv("ZED_TEST_TIMEOUT"))
            except ValueError:
                pass
        
        if os.getenv("ZED_METRICS_RETENTION_DAYS"):
            try:
                self._config.performance.metrics_retention_days = int(os.getenv("ZED_METRICS_RETENTION_DAYS"))
            except ValueError:
                pass
        
        # Monitoring settings
        if os.getenv("ZED_HEALTH_CHECK"):
            self._config.monitoring.health_check_enabled = os.getenv("ZED_HEALTH_CHECK").lower() in ("true", "1", "yes")
        
        if os.getenv("ZED_METRICS_COLLECTION"):
            self._config.monitoring.metrics_collection_enabled = os.getenv("ZED_METRICS_COLLECTION").lower() in ("true", "1", "yes")
    
    def _apply_config_dict(self, data: Dict[str, Any]):
        """Apply configuration from dictionary."""
        # Database configuration
        if "database" in data:
            db_config = data["database"]
            if "timeout_seconds" in db_config:
                self._config.database.timeout_seconds = db_config["timeout_seconds"]
            if "cache_size_mb" in db_config:
                self._config.database.cache_size_mb = db_config["cache_size_mb"]
            if "wal_mode" in db_config:
                self._config.database.wal_mode = db_config["wal_mode"]
            if "optimize_on_connect" in db_config:
                self._config.database.optimize_on_connect = db_config["optimize_on_connect"]
        
        # Security configuration
        if "security" in data:
            sec_config = data["security"]
            if "max_file_size_mb" in sec_config:
                self._config.security.max_file_size_mb = sec_config["max_file_size_mb"]
            if "auto_apply_enabled" in sec_config:
                self._config.security.auto_apply_enabled = sec_config["auto_apply_enabled"]
            if "auto_apply_risk_threshold" in sec_config:
                self._config.security.auto_apply_risk_threshold = sec_config["auto_apply_risk_threshold"]
            if "auto_apply_max_lines" in sec_config:
                self._config.security.auto_apply_max_lines = sec_config["auto_apply_max_lines"]
            if "auto_apply_file_patterns" in sec_config:
                self._config.security.auto_apply_file_patterns = sec_config["auto_apply_file_patterns"]
        
        # Performance configuration
        if "performance" in data:
            perf_config = data["performance"]
            if "fingerprint_cache_size" in perf_config:
                self._config.performance.fingerprint_cache_size = perf_config["fingerprint_cache_size"]
            if "test_timeout_seconds" in perf_config:
                self._config.performance.test_timeout_seconds = perf_config["test_timeout_seconds"]
            if "metrics_retention_days" in perf_config:
                self._config.performance.metrics_retention_days = perf_config["metrics_retention_days"]
        
        # Monitoring configuration
        if "monitoring" in data:
            mon_config = data["monitoring"]
            if "health_check_enabled" in mon_config:
                self._config.monitoring.health_check_enabled = mon_config["health_check_enabled"]
            if "metrics_collection_enabled" in mon_config:
                self._config.monitoring.metrics_collection_enabled = mon_config["metrics_collection_enabled"]
            if "disk_space_warning_mb" in mon_config:
                self._config.monitoring.disk_space_warning_mb = mon_config["disk_space_warning_mb"]
        
        # Global settings
        if "log_level" in data:
            self._config.log_level = data["log_level"].upper()
        if "debug_mode" in data:
            self._config.debug_mode = data["debug_mode"]
    
    @property
    def config(self) -> ShadowVCSConfig:
        """Get the current configuration."""
        return self._config
    
    def save_sample_config(self, path: Path):
        """Save a sample configuration file."""
        sample_config = {
            "# Shadow VCS Configuration": None,
            "# Environment variables take precedence over these settings": None,
            "": None,
            "database": {
                "timeout_seconds": 30,
                "cache_size_mb": 10,
                "wal_mode": True,
                "optimize_on_connect": True
            },
            "security": {
                "max_file_size_mb": 10,
                "auto_apply_enabled": True,
                "auto_apply_risk_threshold": 0.1,
                "auto_apply_max_lines": 10,
                "auto_apply_file_patterns": ["*.md", "*.txt", "*.rst"]
            },
            "performance": {
                "fingerprint_cache_size": 128,
                "test_timeout_seconds": 300,
                "metrics_retention_days": 90
            },
            "monitoring": {
                "health_check_enabled": True,
                "metrics_collection_enabled": True,
                "disk_space_warning_mb": 100
            },
            "log_level": "INFO",
            "debug_mode": False
        }
        
        yaml = YAML()
        yaml.preserve_quotes = True
        yaml.map_indent = 2
        yaml.sequence_indent = 4
        
        with open(path, 'w') as f:
            f.write("# Shadow VCS Configuration\n")
            f.write("# Environment variables take precedence over these settings\n\n")
            yaml.dump({k: v for k, v in sample_config.items() if not k.startswith('#') and k != ''}, f)
    
    def get_env_help(self) -> str:
        """Get help text for environment variables."""
        return """
Environment Variables:
  ZED_CONFIG_PATH           Path to configuration file
  ZED_LOG_LEVEL            Log level (DEBUG, INFO, WARNING, ERROR)
  ZED_DEBUG                Enable debug mode (true/false)
  
  Database:
  ZED_DB_TIMEOUT           Database timeout in seconds
  ZED_DB_CACHE_SIZE_MB     Database cache size in MB
  
  Security:
  ZED_MAX_FILE_SIZE_MB     Maximum file size for commits in MB
  ZED_AUTO_APPLY           Enable auto-apply feature (true/false)
  ZED_AUTO_APPLY_RISK_THRESHOLD  Risk threshold for auto-apply (0.0-1.0)
  
  Performance:
  ZED_TEST_TIMEOUT         Test command timeout in seconds
  ZED_METRICS_RETENTION_DAYS  Days to retain metrics
  
  Monitoring:
  ZED_HEALTH_CHECK         Enable health checks (true/false)
  ZED_METRICS_COLLECTION   Enable metrics collection (true/false)
"""


# Global configuration instance
_config_manager: Optional[ConfigManager] = None


def get_config(repo_path: Optional[Path] = None) -> ShadowVCSConfig:
    """Get the global configuration instance."""
    global _config_manager
    if _config_manager is None or (repo_path and _config_manager.repo_path != repo_path):
        _config_manager = ConfigManager(repo_path)
    return _config_manager.config


def reload_config(repo_path: Optional[Path] = None):
    """Reload configuration from all sources."""
    global _config_manager
    _config_manager = ConfigManager(repo_path)
    return _config_manager.config 