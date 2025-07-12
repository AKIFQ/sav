"""Metrics and monitoring for Shadow VCS."""
import json
import time
from contextlib import contextmanager
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Optional
from threading import Lock

from sav.core.db import connect


@dataclass
class PerformanceMetric:
    """Represents a performance measurement."""
    operation: str
    duration_ms: float
    timestamp: int
    metadata: Dict[str, any] = None


@dataclass
class UsageStats:
    """Aggregated usage statistics."""
    total_commits: int
    auto_approved_commits: int
    manual_approved_commits: int
    rejected_commits: int
    avg_risk_score: float
    total_files_committed: int
    total_lines_added: int
    total_lines_deleted: int
    avg_commit_size: float


class MetricsCollector:
    """Collects and stores performance metrics."""
    
    def __init__(self, repo):
        """Initialize metrics collector."""
        self.repo = repo
        self.metrics_file = repo.sav_dir / "metrics.json"
        self._metrics: List[PerformanceMetric] = []
        self._lock = Lock()
        self._load_metrics()
    
    def _load_metrics(self):
        """Load existing metrics from file."""
        if self.metrics_file.exists():
            try:
                with open(self.metrics_file, 'r') as f:
                    data = json.load(f)
                    self._metrics = [
                        PerformanceMetric(**metric) for metric in data.get('metrics', [])
                    ]
            except Exception:
                self._metrics = []
    
    def _save_metrics(self):
        """Save metrics to file."""
        try:
            # Keep only recent metrics to prevent unbounded file growth
            max_metrics = 1000  # Could be configurable in the future
            recent_metrics = self._metrics[-max_metrics:] if len(self._metrics) > max_metrics else self._metrics
            
            data = {
                'last_updated': int(time.time()),
                'metrics': [asdict(metric) for metric in recent_metrics]
            }
            
            temp_file = self.metrics_file.with_suffix('.tmp')
            with open(temp_file, 'w') as f:
                json.dump(data, f, indent=2)
            
            # Atomic replacement
            temp_file.replace(self.metrics_file)
        except Exception:
            pass  # Metrics are non-critical, don't fail operations
    
    @contextmanager
    def measure_operation(self, operation: str, metadata: Dict = None):
        """Context manager to measure operation duration."""
        start_time = time.time()
        try:
            yield
        finally:
            duration_ms = (time.time() - start_time) * 1000
            self.record_metric(operation, duration_ms, metadata)
    
    def record_metric(self, operation: str, duration_ms: float, metadata: Dict = None):
        """Record a performance metric."""
        metric = PerformanceMetric(
            operation=operation,
            duration_ms=duration_ms,
            timestamp=int(time.time()),
            metadata=metadata or {}
        )
        
        with self._lock:
            self._metrics.append(metric)
            # Save periodically
            if len(self._metrics) % 10 == 0:
                self._save_metrics()
    
    def get_usage_stats(self) -> UsageStats:
        """Get aggregated usage statistics from database."""
        with connect(self.repo.db_path, self.repo.path) as conn:
            cursor = conn.cursor()
            
            # Get commit statistics
            cursor.execute("""
                SELECT 
                    COUNT(*) as total_commits,
                    SUM(CASE WHEN status = 'applied' AND approved_by = 'system' THEN 1 ELSE 0 END) as auto_approved,
                    SUM(CASE WHEN status = 'applied' AND approved_by != 'system' THEN 1 ELSE 0 END) as manual_approved,
                    SUM(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END) as rejected
                FROM commits
            """)
            commit_stats = cursor.fetchone()
            
            # Get fingerprint statistics
            cursor.execute("""
                SELECT 
                    AVG(risk_score) as avg_risk,
                    SUM(files_changed) as total_files,
                    SUM(lines_added) as total_added,
                    SUM(lines_deleted) as total_deleted,
                    AVG(files_changed) as avg_size
                FROM fingerprints
            """)
            fingerprint_stats = cursor.fetchone()
            
            return UsageStats(
                total_commits=commit_stats['total_commits'] or 0,
                auto_approved_commits=commit_stats['auto_approved'] or 0,
                manual_approved_commits=commit_stats['manual_approved'] or 0,
                rejected_commits=commit_stats['rejected'] or 0,
                avg_risk_score=round(fingerprint_stats['avg_risk'] or 0.0, 3),
                total_files_committed=fingerprint_stats['total_files'] or 0,
                total_lines_added=fingerprint_stats['total_added'] or 0,
                total_lines_deleted=fingerprint_stats['total_deleted'] or 0,
                avg_commit_size=round(fingerprint_stats['avg_size'] or 0.0, 1)
            )
    
    def get_performance_summary(self) -> Dict:
        """Get performance metrics summary."""
        if not self._metrics:
            return {}
        
        # Group by operation
        by_operation = {}
        for metric in self._metrics:
            if metric.operation not in by_operation:
                by_operation[metric.operation] = []
            by_operation[metric.operation].append(metric.duration_ms)
        
        # Calculate statistics
        summary = {}
        for operation, durations in by_operation.items():
            durations.sort()
            count = len(durations)
            summary[operation] = {
                'count': count,
                'avg_ms': round(sum(durations) / count, 2),
                'min_ms': round(min(durations), 2),
                'max_ms': round(max(durations), 2),
                'p50_ms': round(durations[count // 2], 2),
                'p95_ms': round(durations[int(count * 0.95)], 2) if count > 5 else round(max(durations), 2)
            }
        
        return summary
    
    def health_check(self) -> Dict:
        """Perform system health check."""
        health = {
            'status': 'healthy',
            'issues': [],
            'timestamp': int(time.time())
        }
        
        # Check database integrity
        from sav.core.db import verify_database_integrity
        if not verify_database_integrity(self.repo.db_path):
            health['status'] = 'degraded'
            health['issues'].append('Database integrity check failed')
        
        # Check disk space
        try:
            from sav.core.config import get_config
            config = get_config(self.repo.path)
            warning_threshold = config.monitoring.disk_space_warning_mb
            
            stats = self.repo.sav_dir.stat()
            import shutil as shutil_disk
            disk_usage = shutil_disk.disk_usage(self.repo.sav_dir)
            free_mb = disk_usage.free / (1024 * 1024)
            
            if free_mb < warning_threshold:
                health['status'] = 'warning'
                health['issues'].append(f'Low disk space: {free_mb:.0f}MB remaining (threshold: {warning_threshold}MB)')
        except Exception:
            pass
        
        # Check for stale commits
        with connect(self.repo.db_path, self.repo.path) as conn:
            cursor = conn.cursor()
            from sav.core.config import get_config
            config = get_config(self.repo.path)
            stale_days = config.monitoring.stale_commit_warning_days
            cutoff_time = int(time.time()) - (stale_days * 24 * 60 * 60)
            
            cursor.execute("""
                SELECT COUNT(*) FROM commits 
                WHERE status = 'waiting_review' AND timestamp < ?
            """, (cutoff_time,))
            stale_commits = cursor.fetchone()[0]
            
            if stale_commits > 0:
                health['status'] = 'warning'
                health['issues'].append(f'{stale_commits} commits pending review for >{stale_days} days')
        
        return health
    
    def cleanup_old_data(self, days_to_keep: int = 90):
        """Clean up old metrics and audit log entries."""
        cutoff_time = int(time.time()) - (days_to_keep * 24 * 60 * 60)
        
        # Clean up old audit log entries
        with connect(self.repo.db_path, self.repo.path) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM audit_log WHERE timestamp < ?", (cutoff_time,))
            deleted_logs = cursor.rowcount
            conn.commit()
        
        # Clean up old metrics
        with self._lock:
            original_count = len(self._metrics)
            self._metrics = [m for m in self._metrics if m.timestamp >= cutoff_time]
            deleted_metrics = original_count - len(self._metrics)
            self._save_metrics()
        
        return {
            'deleted_audit_logs': deleted_logs,
            'deleted_metrics': deleted_metrics
        } 