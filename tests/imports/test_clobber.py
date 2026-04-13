import pwn
import dog

# Names that dog is allowed to shadow from pwntools.
# Add entries here if a clobber is intentional.
CLOBBER_WHITELIST = set()


def _star_exports(module):
    if hasattr(module, "__all__"):
        return set(module.__all__)
    return {n for n in dir(module) if not n.startswith("_")}


def test_no_pwntools_clobber():
    pwn_names = _star_exports(pwn)
    dog_names = _star_exports(dog)

    clobbered = [
        name
        for name in sorted(pwn_names & dog_names)
        if name not in CLOBBER_WHITELIST
        and getattr(pwn, name) is not getattr(dog, name)
    ]

    assert not clobbered, (
        "dog clobbers the following pwntools names:\n"
        + "\n".join(f"  {name}" for name in clobbered)
    )
