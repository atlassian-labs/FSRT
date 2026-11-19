//! What the source says about one Atlassian REST request.
//!
//! The lowering records the HTTP method and route text of every
//! `requestJira`, `requestConfluence` and `requestBitbucket` call from the AST,
//! where the call's arguments are intact. Values that are not written inline
//! are carried as references to a `const` binding and resolved against the
//! environment when a policy asks, so declaration order does not matter. Anything the
//! lowering cannot prove stays `Unknown`; a policy must treat that as the
//! most privileged alternative.

use swc_core::ecma::atoms::Atom;

use crate::definitions::{DefId, Environment};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
    /// Any other literal method, such as HEAD or a misspelling.
    Other,
}

impl HttpMethod {
    pub(crate) fn from_literal(value: &str) -> Self {
        match value.to_ascii_uppercase().as_str() {
            "GET" => Self::Get,
            "POST" => Self::Post,
            "PUT" => Self::Put,
            "PATCH" => Self::Patch,
            "DELETE" => Self::Delete,
            _ => Self::Other,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
            Self::Other => "OTHER",
        }
    }
}

/// A piece of route text: a literal, or an expression whose value is not known.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Piece {
    Text(Atom),
    Hole,
}

/// Route text with its holes, such as `/rest/api/3/issue/${key}?expand=names`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RouteText(Vec<Piece>);

impl RouteText {
    pub(crate) fn new(pieces: impl IntoIterator<Item = Piece>) -> Self {
        let mut merged: Vec<Piece> = Vec::new();
        for piece in pieces {
            match (merged.last_mut(), piece) {
                (Some(Piece::Text(last)), Piece::Text(next)) => {
                    *last = format!("{last}{next}").into();
                }
                (Some(Piece::Hole), Piece::Hole) => {}
                (_, Piece::Text(next)) if next.is_empty() => {}
                (_, piece) => merged.push(piece),
            }
        }
        Self(merged)
    }

    pub(crate) fn concat(self, other: Self) -> Self {
        Self::new(self.0.into_iter().chain(other.0))
    }

    pub fn pieces(&self) -> &[Piece] {
        &self.0
    }

    /// The route as written, with `${}` standing for each unknown part.
    pub fn display(&self) -> String {
        self.0
            .iter()
            .map(|piece| match piece {
                Piece::Text(text) => text.as_ref(),
                Piece::Hole => "${}",
            })
            .collect()
    }

    /// The path before any query string, as slash-separated segments. A segment
    /// containing a hole is `None`.
    pub fn path_segments(&self) -> Vec<Option<String>> {
        let mut segments: Vec<Option<String>> = vec![Some(String::new())];
        'pieces: for piece in &self.0 {
            match piece {
                Piece::Hole => *segments.last_mut().unwrap() = None,
                Piece::Text(text) => {
                    for (index, part) in text.split('/').enumerate() {
                        if index > 0 {
                            segments.push(Some(String::new()));
                        }
                        let (part, query) = match part.split_once(['?', '#']) {
                            Some((path, _)) => (path, true),
                            None => (part, false),
                        };
                        if let Some(Some(segment)) = segments.last_mut() {
                            segment.push_str(part);
                        }
                        if query {
                            break 'pieces;
                        }
                    }
                }
            }
        }
        // `/a/b/` and `/a/b` name the same resource, and the leading `/` leaves
        // an empty first segment.
        segments.retain(|segment| segment.as_deref() != Some(""));
        segments
    }

    /// The query string's text, with each hole standing for an unknown value,
    /// or `None` when the route has no query string.
    pub fn query(&self) -> Option<Vec<Piece>> {
        let mut query: Option<Vec<Piece>> = None;
        for piece in &self.0 {
            match (piece, &mut query) {
                (Piece::Text(text), None) => {
                    if let Some((_, rest)) = text.split_once(['?', '#']) {
                        query = Some(vec![Piece::Text(rest.into())]);
                    }
                }
                (piece, Some(query)) => query.push(piece.clone()),
                _ => {}
            }
        }
        query
    }
}

/// A fact about a request argument.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fact<T> {
    Known(T),
    /// Written as the identifier of a `const` binding.
    Binding(DefId),
    Unknown,
}

/// The method and route a request names. Requests that do not state a method
/// use GET.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestFacts {
    pub route: Fact<RouteText>,
    pub method: Fact<HttpMethod>,
}

impl RequestFacts {
    /// The method, once a `const` binding is looked up. `None` when unknown.
    pub fn method(&self, env: &Environment) -> Option<HttpMethod> {
        match &self.method {
            Fact::Known(method) => Some(*method),
            Fact::Binding(def) => env.authz_consts.get(def)?.method,
            Fact::Unknown => None,
        }
    }

    /// The route text, once a `const` binding is looked up. `None` when unknown.
    pub fn route<'a>(&'a self, env: &'a Environment) -> Option<&'a RouteText> {
        match &self.route {
            Fact::Known(route) => Some(route),
            Fact::Binding(def) => env.authz_consts.get(def)?.route.as_ref(),
            Fact::Unknown => None,
        }
    }
}

/// What a `const` initializer says about request arguments.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ConstFacts {
    pub route: Option<RouteText>,
    pub method: Option<HttpMethod>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(value: &str) -> Piece {
        Piece::Text(value.into())
    }

    #[test]
    fn splits_path_and_query_around_holes() {
        let route = RouteText::new([
            text("/rest/api/3/issue/"),
            Piece::Hole,
            text("/comment?expand="),
            Piece::Hole,
        ]);
        assert_eq!(
            route.path_segments(),
            [
                Some("rest".into()),
                Some("api".into()),
                Some("3".into()),
                Some("issue".into()),
                None,
                Some("comment".into()),
            ]
        );
        assert_eq!(route.query(), Some(vec![text("expand="), Piece::Hole]));
        assert_eq!(route.display(), "/rest/api/3/issue/${}/comment?expand=${}");
    }

    #[test]
    fn a_hole_inside_a_segment_makes_the_whole_segment_unknown() {
        let route = RouteText::new([text("/rest/api/3/"), Piece::Hole, text("field")]);
        assert_eq!(route.path_segments().last(), Some(&None));
        let slash = RouteText::new([text("/rest/api/3/"), Piece::Hole, text("/field")]);
        assert_eq!(
            slash
                .path_segments()
                .iter()
                .rev()
                .take(2)
                .collect::<Vec<_>>(),
            [&Some("field".to_string()), &None]
        );
    }

    #[test]
    fn trailing_slashes_and_missing_queries_are_ignored() {
        let route = RouteText::new([text("/rest/api/3/field/")]);
        assert_eq!(route.path_segments().len(), 4);
        assert_eq!(route.query(), None);
    }
}
