/// A trait for writing to a builder type. This is the pattern used to write Cap'n Proto messages.
///
/// `bldr` must be freshly initialised (from `init_root`, an `init_*` call or a new
/// list element). `write_to` sets every field the value carries and leaves the rest
/// alone, so an optional field that is `None` (for example `Link::peer`) stays unset
/// only because the builder starts empty. Writing into a builder that was already
/// written could leave a stale value from the earlier write.
pub trait WriteTo<Bldr> {
    fn write_to(&self, bldr: &mut Bldr);
}
