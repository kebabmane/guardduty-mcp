"""Configuration management for GuardDuty MCP Server."""

import os
from typing import Any, Dict, Optional

from dotenv import load_dotenv
from pydantic import Field
from pydantic_settings import BaseSettings

# Load environment variables from .env file
load_dotenv()


class AWSConfig(BaseSettings):
    """AWS configuration settings."""
    
    region: str = Field(default="us-east-1", env="AWS_REGION")
    access_key_id: Optional[str] = Field(default=None, env="AWS_ACCESS_KEY_ID")
    secret_access_key: Optional[str] = Field(default=None, env="AWS_SECRET_ACCESS_KEY")
    session_token: Optional[str] = Field(default=None, env="AWS_SESSION_TOKEN")
    profile: Optional[str] = Field(default=None, env="AWS_PROFILE")

    class Config:
        env_prefix = "AWS_"


class GuardDutyConfig(BaseSettings):
    """GuardDuty specific configuration."""
    
    detector_id: Optional[str] = Field(default=None, env="GUARDDUTY_DETECTOR_ID")
    default_max_results: int = Field(default=50, env="GUARDDUTY_MAX_RESULTS")
    default_severity_filter: str = Field(
        default="HIGH,MEDIUM,LOW", env="GUARDDUTY_SEVERITY_FILTER"
    )

    @property
    def severity_list(self) -> list[str]:
        """Get severity filter as a list."""
        return [s.strip() for s in self.default_severity_filter.split(",")]

    class Config:
        env_prefix = "GUARDDUTY_"




class LoggingConfig(BaseSettings):
    """Logging configuration settings."""
    
    level: str = Field(default="INFO", env="LOG_LEVEL")
    format: str = Field(
        default="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        env="LOG_FORMAT",
    )
    file_path: Optional[str] = Field(default=None, env="LOG_FILE_PATH")

    class Config:
        env_prefix = "LOG_"


class SecurityConfig(BaseSettings):
    """Security configuration settings."""
    
    enable_audit_logging: bool = Field(default=False, env="ENABLE_AUDIT_LOGGING")
    audit_log_path: str = Field(default="./logs/audit.log", env="AUDIT_LOG_PATH")
    sensitive_fields_redaction: bool = Field(
        default=True, env="SENSITIVE_FIELDS_REDACTION"
    )
    max_retry_attempts: int = Field(default=3, env="MAX_RETRY_ATTEMPTS")

    class Config:
        env_prefix = "SECURITY_"


class Config:
    """Main configuration class that combines all config sections."""
    
    def __init__(self) -> None:
        self.aws = AWSConfig()
        self.guardduty = GuardDutyConfig()
        self.logging = LoggingConfig()
        self.security = SecurityConfig()

    def validate_required_settings(self) -> None:
        """Validate that required settings are present."""
        missing_settings = []
        
        # Check AWS credentials (either access keys or profile)
        if not self.aws.profile and not (
            self.aws.access_key_id and self.aws.secret_access_key
        ):
            missing_settings.append(
                "AWS credentials: Set either AWS_PROFILE or both "
                "AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY"
            )
        
        
        if missing_settings:
            raise ValueError(
                f"Missing required configuration: {', '.join(missing_settings)}"
            )

    def get_aws_session_config(self) -> Dict[str, Any]:
        """Get AWS session configuration for boto3."""
        config = {"region_name": self.aws.region}
        
        if self.aws.profile:
            config["profile_name"] = self.aws.profile
        elif self.aws.access_key_id and self.aws.secret_access_key:
            config["aws_access_key_id"] = self.aws.access_key_id
            config["aws_secret_access_key"] = self.aws.secret_access_key
            if self.aws.session_token:
                config["aws_session_token"] = self.aws.session_token
        
        return config


    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary (for serialization)."""
        return {
            "aws": self.aws.dict(),
            "guardduty": self.guardduty.dict(),
            "logging": self.logging.dict(),
            "security": self.security.dict(),
        }


# Global configuration instance
config = Config()


def get_config() -> Config:
    """Get the global configuration instance."""
    return config


def validate_config() -> None:
    """Validate the global configuration."""
    config.validate_required_settings()