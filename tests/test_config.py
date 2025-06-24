"""Tests for configuration management."""

import os
import pytest
from unittest.mock import patch

from guardduty_agent.config import Config, AWSConfig, GuardDutyConfig, AgentConfig


class TestAWSConfig:
    """Test AWS configuration."""

    def test_default_values(self):
        """Test default configuration values."""
        config = AWSConfig()
        assert config.region == "us-east-1"
        assert config.access_key_id is None
        assert config.secret_access_key is None

    @patch.dict(os.environ, {
        "AWS_REGION": "us-west-2",
        "AWS_ACCESS_KEY_ID": "test-key",
        "AWS_SECRET_ACCESS_KEY": "test-secret"
    })
    def test_env_values(self):
        """Test configuration from environment variables."""
        config = AWSConfig()
        assert config.region == "us-west-2"
        assert config.access_key_id == "test-key"
        assert config.secret_access_key == "test-secret"


class TestGuardDutyConfig:
    """Test GuardDuty configuration."""

    def test_default_values(self):
        """Test default configuration values."""
        config = GuardDutyConfig()
        assert config.detector_id is None
        assert config.default_max_results == 50
        assert config.default_severity_filter == "HIGH,MEDIUM,LOW"

    def test_severity_list(self):
        """Test severity list property."""
        config = GuardDutyConfig()
        assert config.severity_list == ["HIGH", "MEDIUM", "LOW"]

    @patch.dict(os.environ, {
        "GUARDDUTY_DETECTOR_ID": "test-detector",
        "GUARDDUTY_MAX_RESULTS": "100",
        "GUARDDUTY_SEVERITY_FILTER": "HIGH,MEDIUM"
    })
    def test_env_values(self):
        """Test configuration from environment variables."""
        config = GuardDutyConfig()
        assert config.detector_id == "test-detector"
        assert config.default_max_results == 100
        assert config.severity_list == ["HIGH", "MEDIUM"]


class TestAgentConfig:
    """Test Agent configuration."""

    def test_default_values(self):
        """Test default configuration values."""
        config = AgentConfig()
        assert config.name == "GuardDuty Security Agent"
        assert config.model == "anthropic/claude-3-5-sonnet-20241022"
        assert config.max_tokens == 4000
        assert config.temperature == 0.1

    @patch.dict(os.environ, {
        "AGENT_NAME": "Custom Agent",
        "AGENT_MODEL": "anthropic/claude-3-haiku-20240307",
        "AGENT_MAX_TOKENS": "2000",
        "AGENT_TEMPERATURE": "0.5"
    })
    def test_env_values(self):
        """Test configuration from environment variables."""
        config = AgentConfig()
        assert config.name == "Custom Agent"
        assert config.model == "anthropic/claude-3-haiku-20240307"
        assert config.max_tokens == 2000
        assert config.temperature == 0.5


class TestConfig:
    """Test main configuration class."""

    def test_initialization(self):
        """Test configuration initialization."""
        config = Config()
        assert isinstance(config.aws, AWSConfig)
        assert isinstance(config.guardduty, GuardDutyConfig)
        assert isinstance(config.agent, AgentConfig)

    @patch.dict(os.environ, {
        "AWS_PROFILE": "test-profile"
    })
    def test_validate_with_profile(self):
        """Test validation with AWS profile."""
        config = Config()
        # Should not raise exception
        config.validate_required_settings()

    @patch.dict(os.environ, {
        "AWS_ACCESS_KEY_ID": "test-key",
        "AWS_SECRET_ACCESS_KEY": "test-secret"
    })
    def test_validate_with_keys(self):
        """Test validation with AWS access keys."""
        config = Config()
        # Should not raise exception
        config.validate_required_settings()

    def test_validate_missing_credentials(self):
        """Test validation with missing AWS credentials."""
        with patch.dict(os.environ, {}, clear=True):
            config = Config()
            with pytest.raises(ValueError, match="Missing required configuration"):
                config.validate_required_settings()

    @patch.dict(os.environ, {
        "AWS_PROFILE": "test-profile",
        "AWS_REGION": "eu-west-1"
    })
    def test_get_aws_session_config_with_profile(self):
        """Test AWS session config with profile."""
        config = Config()
        session_config = config.get_aws_session_config()
        
        assert session_config["region_name"] == "eu-west-1"
        assert session_config["profile_name"] == "test-profile"
        assert "aws_access_key_id" not in session_config

    @patch.dict(os.environ, {
        "AWS_ACCESS_KEY_ID": "test-key",
        "AWS_SECRET_ACCESS_KEY": "test-secret",
        "AWS_SESSION_TOKEN": "test-token"
    })
    def test_get_aws_session_config_with_keys(self):
        """Test AWS session config with access keys."""
        config = Config()
        session_config = config.get_aws_session_config()
        
        assert session_config["aws_access_key_id"] == "test-key"
        assert session_config["aws_secret_access_key"] == "test-secret"
        assert session_config["aws_session_token"] == "test-token"
        assert "profile_name" not in session_config

    def test_get_agent_config(self):
        """Test getting agent configuration."""
        config = Config()
        agent_config = config.get_agent_config()
        
        assert "name" in agent_config
        assert "model" in agent_config
        assert "max_tokens" in agent_config
        assert "aws_region" in agent_config

    def test_to_dict(self):
        """Test configuration serialization."""
        config = Config()
        config_dict = config.to_dict()
        
        assert "aws" in config_dict
        assert "guardduty" in config_dict
        assert "agent" in config_dict
        assert "logging" in config_dict
        assert "security" in config_dict