"""Plugin registry for tool discovery plugins."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .errors import RegistryError
from .models import ToolDescriptor

if TYPE_CHECKING:
    from mindjack.discovery.base import ToolPlugin


class PluginRegistry:
    """Central registry for tool discovery plugins."""

    def __init__(self) -> None:
        self._plugins: dict[str, ToolPlugin] = {}
        self._descriptors: dict[str, ToolDescriptor] = {}

    def register(self, plugin: ToolPlugin) -> None:
        slug = plugin.slug
        if slug in self._plugins:
            raise RegistryError(f"Plugin already registered: {slug}")
        self._plugins[slug] = plugin
        self._descriptors[slug] = plugin.descriptor

    def get(self, slug: str) -> ToolPlugin:
        try:
            return self._plugins[slug]
        except KeyError:
            raise RegistryError(f"Unknown plugin: {slug}") from None

    def all_plugins(self) -> list[ToolPlugin]:
        return list(self._plugins.values())

    def all_slugs(self) -> list[str]:
        return list(self._plugins.keys())

    def descriptor(self, slug: str) -> ToolDescriptor:
        try:
            return self._descriptors[slug]
        except KeyError:
            raise RegistryError(f"Unknown plugin: {slug}") from None


# Singleton registry, populated by load_default_plugins()
_registry = PluginRegistry()


def get_registry() -> PluginRegistry:
    return _registry


def load_default_plugins() -> PluginRegistry:
    """Import and register all built-in discovery plugins."""
    from mindjack.discovery import (
        amazon_q,
        claude_code,
        cline,
        codex_cli,
        continue_dev,
        copilot,
        cross_tool,
        cursor,
        roo_code,
        windsurf,
    )

    for mod in (
        claude_code,
        codex_cli,
        cursor,
        copilot,
        continue_dev,
        cline,
        roo_code,
        amazon_q,
        windsurf,
        cross_tool,
    ):
        plugin = mod.create_plugin()
        if plugin.slug not in _registry._plugins:
            _registry.register(plugin)

    return _registry
