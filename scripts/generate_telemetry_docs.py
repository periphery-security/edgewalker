#!/usr/bin/env python3
"""Generate JSON schemas for EdgeWalker telemetry models."""

# Standard Library
import json
import os
import sys
import tempfile
from pathlib import Path

# Use a temporary directory for config/cache/data during schema generation
# to avoid PermissionError on live config directories in some environments.
temp_dir = tempfile.TemporaryDirectory()
os.environ["EW_CONFIG_DIR"] = str(Path(temp_dir.name) / "config")
os.environ["EW_CACHE_DIR"] = str(Path(temp_dir.name) / "cache")
os.environ["EW_DATA_DIR"] = str(Path(temp_dir.name) / "data")

# Third Party
import semver  # noqa: E402
from pydantic.json_schema import GenerateJsonSchema, JsonSchemaValue  # noqa: E402
from pydantic_core import core_schema  # noqa: E402

# Add src to path so we can import edgewalker
sys.path.append(str(Path(__file__).parent.parent / "src"))

# First Party
from edgewalker.modules.cve_scan.models import CveScanModel  # noqa: E402
from edgewalker.modules.password_scan.models import PasswordScanModel  # noqa: E402
from edgewalker.modules.port_scan.models import PortScanModel  # noqa: E402
from edgewalker.modules.sql_scan.models import SqlScanModel  # noqa: E402
from edgewalker.modules.web_scan.models import WebScanModel  # noqa: E402


class CustomGenerateJsonSchema(GenerateJsonSchema):
    """Custom JSON schema generator for Pydantic models."""

    def is_instance_schema(self, schema: core_schema.IsInstanceSchema) -> JsonSchemaValue:
        """Handle custom instance schemas, specifically for semver.VersionInfo."""
        if schema["cls"] == semver.VersionInfo:
            return {"type": "string", "format": "semver"}
        return super().is_instance_schema(schema)


def generate_schemas() -> None:
    """Generate JSON schemas for all telemetry models."""
    output_dir = Path(__file__).parent.parent / "docs" / "telemetry_samples"
    output_dir.mkdir(parents=True, exist_ok=True)

    models = {
        "port_scan": PortScanModel,
        "password_scan": PasswordScanModel,
        "cve_scan": CveScanModel,
        "sql_scan": SqlScanModel,
        "web_scan": WebScanModel,
    }

    for name, model_class in models.items():
        # Use our custom schema generator to handle semver.VersionInfo
        schema = model_class.model_json_schema(schema_generator=CustomGenerateJsonSchema)

        # Add some metadata
        schema["title"] = f"EdgeWalker {name.replace('_', ' ').title()} Telemetry Schema"

        output_path = output_dir / f"{name}_schema.json"
        with open(output_path, "w") as f:
            json.dump(schema, f, indent=2)
            f.write("\n")

        print("Schema generated.")


if __name__ == "__main__":
    generate_schemas()
