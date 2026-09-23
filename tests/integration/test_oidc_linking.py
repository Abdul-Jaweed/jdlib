import uuid

import sqlalchemy as sa

from jdlib.authn.oidc import IdentityClaims, UserLinker
from jdlib.config import OidcConfig
from jdlib.control.models import IdentityLink, User


def _config(*, trusted: bool) -> OidcConfig:
    return OidcConfig(issuer="https://idp", audience="a", email_trusted=trusted)


def _racing_factory(factory, race):
    def make():
        session = factory()
        original = session.commit
        fired = False

        async def commit():
            nonlocal fired
            if not fired:
                fired = True
                await race()
            await original()

        session.commit = commit
        return session

    return make


async def test_link_by_identity_link(control_session_factory):
    user_id = uuid.uuid4()
    async with control_session_factory() as session:
        session.add(User(id=user_id, email="known@example.com", status="active"))
        await session.flush()
        session.add(
            IdentityLink(
                id=uuid.uuid4(), user_id=user_id, issuer="https://idp", subject="sub-1"
            )
        )
        await session.commit()
    linker = UserLinker(control_session_factory, _config(trusted=False))
    user = await linker.link(
        IdentityClaims(issuer="https://idp", subject="sub-1", email=None, email_verified=False)
    )
    assert user is not None and user.id == user_id


async def test_link_by_trusted_email(control_session_factory):
    user_id = uuid.uuid4()
    async with control_session_factory() as session:
        session.add(User(id=user_id, email="trusted@example.com", status="active"))
        await session.commit()
    linker = UserLinker(control_session_factory, _config(trusted=True))
    user = await linker.link(
        IdentityClaims(
            issuer="https://idp", subject="sub-2", email="trusted@example.com", email_verified=True
        )
    )
    assert user is not None and user.id == user_id
    async with control_session_factory() as session:
        link = (
            await session.execute(
                sa.select(IdentityLink).where(
                    IdentityLink.user_id == user_id, IdentityLink.subject == "sub-2"
                )
            )
        ).scalar_one()
    assert link.issuer == "https://idp"


async def test_untrusted_or_unverified_email_does_not_link(control_session_factory):
    user_id = uuid.uuid4()
    async with control_session_factory() as session:
        session.add(User(id=user_id, email="plain@example.com", status="active"))
        await session.commit()
    untrusted = UserLinker(control_session_factory, _config(trusted=False))
    untrusted_claims = IdentityClaims(
        issuer="https://idp",
        subject="sub-3",
        email="plain@example.com",
        email_verified=True,
    )
    assert await untrusted.link(untrusted_claims) is None
    trusted = UserLinker(control_session_factory, _config(trusted=True))
    unverified_claims = IdentityClaims(
        issuer="https://idp",
        subject="sub-4",
        email="plain@example.com",
        email_verified=False,
    )
    assert await trusted.link(unverified_claims) is None


async def test_no_silent_provisioning(control_session_factory):
    linker = UserLinker(control_session_factory, _config(trusted=True))
    claims = IdentityClaims(
        issuer="https://idp",
        subject="sub-5",
        email="nobody@example.com",
        email_verified=True,
    )
    assert await linker.link(claims) is None


async def test_link_race_returns_winning_user(control_session_factory):
    email_user_id = uuid.uuid4()
    winner_id = uuid.uuid4()
    async with control_session_factory() as session:
        session.add(User(id=email_user_id, email="race@example.com", status="active"))
        session.add(User(id=winner_id, email="winner@example.com", status="active"))
        await session.commit()

    async def race() -> None:
        async with control_session_factory() as other:
            other.add(
                IdentityLink(
                    id=uuid.uuid4(), user_id=winner_id, issuer="https://idp", subject="sub-race"
                )
            )
            await other.commit()

    linker = UserLinker(_racing_factory(control_session_factory, race), _config(trusted=True))
    user = await linker.link(
        IdentityClaims(
            issuer="https://idp",
            subject="sub-race",
            email="race@example.com",
            email_verified=True,
        )
    )
    assert user is not None and user.id == winner_id
    async with control_session_factory() as session:
        links = (
            (
                await session.execute(
                    sa.select(IdentityLink).where(IdentityLink.subject == "sub-race")
                )
            )
            .scalars()
            .all()
        )
    assert len(links) == 1
    assert links[0].user_id == winner_id


async def test_link_race_user_deleted_returns_none(control_session_factory):
    user_id = uuid.uuid4()
    async with control_session_factory() as session:
        session.add(User(id=user_id, email="gone@example.com", status="active"))
        await session.commit()

    async def race() -> None:
        async with control_session_factory() as other:
            await other.execute(sa.delete(User).where(User.id == user_id))
            await other.commit()

    linker = UserLinker(_racing_factory(control_session_factory, race), _config(trusted=True))
    user = await linker.link(
        IdentityClaims(
            issuer="https://idp",
            subject="sub-gone",
            email="gone@example.com",
            email_verified=True,
        )
    )
    assert user is None


async def test_identity_link_wins_over_trusted_email_match(control_session_factory):
    linked_id = uuid.uuid4()
    email_id = uuid.uuid4()
    async with control_session_factory() as session:
        session.add(User(id=linked_id, email="linked@example.com", status="active"))
        session.add(User(id=email_id, email="shared@example.com", status="active"))
        await session.flush()
        session.add(
            IdentityLink(
                id=uuid.uuid4(), user_id=linked_id, issuer="https://idp", subject="sub-precedence"
            )
        )
        await session.commit()

    linker = UserLinker(control_session_factory, _config(trusted=True))
    user = await linker.link(
        IdentityClaims(
            issuer="https://idp",
            subject="sub-precedence",
            email="shared@example.com",
            email_verified=True,
        )
    )
    assert user is not None and user.id == linked_id
    async with control_session_factory() as session:
        links = (
            (
                await session.execute(
                    sa.select(IdentityLink).where(IdentityLink.subject == "sub-precedence")
                )
            )
            .scalars()
            .all()
        )
    assert len(links) == 1
    assert links[0].user_id == linked_id


async def test_linked_inactive_user_denied(control_session_factory):
    user_id = uuid.uuid4()
    async with control_session_factory() as session:
        session.add(User(id=user_id, email="suspended@example.com", status="suspended"))
        await session.flush()
        session.add(
            IdentityLink(
                id=uuid.uuid4(), user_id=user_id, issuer="https://idp", subject="sub-inactive"
            )
        )
        await session.commit()

    linker = UserLinker(control_session_factory, _config(trusted=True))
    claims = IdentityClaims(
        issuer="https://idp",
        subject="sub-inactive",
        email="suspended@example.com",
        email_verified=True,
    )
    assert await linker.link(claims) is None
