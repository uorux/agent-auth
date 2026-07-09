from __future__ import annotations

import asyncio
import logging

import uvicorn

from .api.app import create_app
from .config import Settings, get_settings
from .core.a2a import A2AThreadService
from .core.events import KeyedEvents
from .core.scheduler import ExpiryScheduler
from .core.service import RequestService
from .crypto import SecretBox
from .db import Database
from .discord_bot.bot import AgentAuthBot, DiscordNotifier
from .policy.engine import PolicyEngine
from .policy.llm import LLMEvaluator
from .policy.schema import load_policy
from .provisioners.a2a import A2AProvisioner
from .provisioners.base import ProvisionerRegistry
from .provisioners.github import GithubProvisioner
from .provisioners.google_stub import GoogleStubProvisioner
from .provisioners.kubernetes import KubernetesProvisioner
from .provisioners.lldap import LldapProvisioner

log = logging.getLogger(__name__)


def migrate(settings: Settings) -> None:
    """Run alembic upgrade head against the packaged migrations."""
    from pathlib import Path

    from alembic import command
    from alembic.config import Config

    cfg = Config()
    cfg.set_main_option("script_location", str(Path(__file__).parent / "migrations"))
    cfg.set_main_option("sqlalchemy.url", settings.database_url)
    command.upgrade(cfg, "head")


def build_registry(settings: Settings, policy) -> ProvisionerRegistry:
    registry = ProvisionerRegistry()
    registry.register(A2AProvisioner())
    registry.register(GoogleStubProvisioner())
    if settings.github_app_id and settings.github_app_private_key_file:
        if not settings.encryption_key:
            raise SystemExit("ENCRYPTION_KEY is required when GitHub is enabled")
        registry.register(
            GithubProvisioner(
                app_id=settings.github_app_id,
                private_key_file=settings.github_app_private_key_file,
                api_url=settings.github_api_url,
                config=policy.platforms.github,
                secret_box=SecretBox(settings.encryption_key),
                # optional pin; unset → resolved per repo (multi-installation)
                installation_id=settings.github_installation_id,
            )
        )
    else:
        log.info("github provisioner disabled (GITHUB_APP_ID not set)")
    if settings.lldap_url:
        registry.register(
            LldapProvisioner(
                url=settings.lldap_url,
                admin_user=settings.lldap_admin_user,
                admin_password=settings.lldap_admin_password,
                config=policy.platforms.homelab,
            )
        )
    else:
        log.info("homelab provisioner disabled (LLDAP_URL not set)")
    if settings.kubernetes_api_url:
        registry.register(
            KubernetesProvisioner(
                api_url=settings.kubernetes_api_url,
                config=policy.platforms.kubernetes,
                token=settings.kubernetes_token,
                token_file=settings.kubernetes_token_file,
                ca_file=settings.kubernetes_ca_file,
                insecure_skip_verify=settings.kubernetes_insecure_skip_verify,
            )
        )
    else:
        log.info("kubernetes provisioner disabled (KUBERNETES_API_URL not set)")
    return registry


async def serve(settings: Settings) -> None:
    logging.basicConfig(
        level=settings.log_level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    policy = load_policy(settings.policy_file)
    db = Database(settings.database_url)
    events = KeyedEvents()
    registry = build_registry(settings, policy)
    llm = (
        LLMEvaluator(
            settings.openrouter_api_key,
            settings.openrouter_base_url,
            policy.llm.timeout_secs,
        )
        if settings.openrouter_api_key
        else None
    )
    if llm is None:
        log.info("llm evaluator disabled (OPENROUTER_API_KEY not set); 'llm' rules escalate to human")

    service = RequestService(db, PolicyEngine(policy), registry, events, llm=llm)
    a2a = A2AThreadService(db, settings, KeyedEvents())
    app = create_app(settings, db, service, registry, events, a2a)
    scheduler = ExpiryScheduler(service, a2a)

    server = uvicorn.Server(
        uvicorn.Config(
            app, host=settings.listen_host, port=settings.listen_port, log_level="info"
        )
    )

    tasks = [
        asyncio.create_task(server.serve(), name="api"),
        asyncio.create_task(scheduler.run(), name="scheduler"),
    ]

    bot: AgentAuthBot | None = None
    if settings.discord_token:
        bot = AgentAuthBot(settings, db, service)
        service.set_notifier(DiscordNotifier(bot, db, settings))
        tasks.append(asyncio.create_task(bot.start(settings.discord_token), name="discord"))
    else:
        log.warning(
            "DISCORD_TOKEN not set — running headless; surfaced requests are only "
            "visible via the admin API"
        )

    try:
        done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            if task.exception():
                raise task.exception()
    finally:
        scheduler.stop()
        if bot is not None and not bot.is_closed():
            await bot.close()
        server.should_exit = True
        for task in tasks:
            task.cancel()
        await db.dispose()


def run() -> None:
    settings = get_settings()
    migrate(settings)
    asyncio.run(serve(settings))


if __name__ == "__main__":
    run()
