#![forbid(unsafe_code)]
use core::fmt;
use std::any::type_name;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Wrapper type changing the default debug output to redact the value in logging
#[derive(Default, Hash, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
#[repr(transparent)]
pub struct Secret<T: ?Sized>(T);

impl<T> Secret<T> {
    /// creates a new Secret containing the passed value
    #[inline]
    #[must_use = "the secret will be dropped if not used"]
    pub const fn new(secret: T) -> Self {
        Self(secret)
    }

    /// convert into Secret
    #[inline]
    #[must_use]
    pub fn from(secret: impl Into<T>) -> Self {
        Self(secret.into())
    }

    /// convert into Secret
    #[inline]
    pub fn try_from<U: TryInto<T>>(secret: U) -> Result<Self, Secret<U::Error>> {
        secret.try_into().map(Self).map_err(Secret)
    }

    /// retreive the actual value of the secret
    #[inline]
    #[must_use = "expose_secret does nothing unless used"]
    pub const fn expose_secret(&self) -> &T {
        &self.0
    }
}

impl<T> From<T> for Secret<T> {
    #[inline]
    fn from(secret: T) -> Self {
        Self::new(secret)
    }
}

impl<T> fmt::Debug for Secret<T> {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[REDACTED: {}]", type_name::<T>())
    }
}

impl<T> From<Option<Secret<T>>> for Secret<Option<T>> {
    #[inline]
    fn from(secret: Option<Secret<T>>) -> Self {
        Self(secret.map(|Secret(s)| s))
    }
}

impl<T, E> From<Result<Secret<T>, E>> for Secret<Result<T, E>> {
    #[inline]
    fn from(secret: Result<Secret<T>, E>) -> Self {
        Self(secret.map(|Secret(s)| s))
    }
}

impl<T, E> From<Result<T, Secret<E>>> for Secret<Result<T, E>> {
    #[inline]
    fn from(secret: Result<T, Secret<E>>) -> Self {
        Self(secret.map_err(|Secret(s)| s))
    }
}

impl<T, E> From<Result<Secret<T>, Secret<E>>> for Secret<Result<T, E>> {
    #[inline]
    fn from(secret: Result<Secret<T>, Secret<E>>) -> Self {
        Self(secret.map(|Secret(s)| s).map_err(|Secret(s)| s))
    }
}

impl<S: FromIterator<T>, T> FromIterator<Secret<T>> for Secret<S> {
    #[inline]
    fn from_iter<I: IntoIterator<Item = Secret<T>>>(iter: I) -> Self {
        Self(S::from_iter(iter.into_iter().map(|Secret(s)| s)))
    }
}

// Serde

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Secret<T> {
    #[inline]
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        T::deserialize(deserializer).map(Self)
    }
}

/// Helper trait to allw serde compat
pub trait SerializableSecret<T> {
    /// Helper trait to allw serde compat
    type Exposed<'a>: Serialize
    where
        Self: 'a;
    /// To reduce the number of functions that are able to expose secrets we require
    /// that the [`Secret::expose_secret`] function is passed in here.
    fn expose_via(&self, expose: impl Fn(&Secret<T>) -> &T) -> Self::Exposed<'_>;
}

impl<T: Serialize> SerializableSecret<T> for &Secret<T> {
    type Exposed<'a>
        = &'a T
    where
        T: 'a,
        Self: 'a;

    fn expose_via(&self, expose: impl Fn(&Secret<T>) -> &T) -> Self::Exposed<'_> {
        expose(self)
    }
}

impl<T: Serialize> SerializableSecret<T> for Secret<T> {
    type Exposed<'a>
        = &'a T
    where
        T: 'a;

    fn expose_via(&self, expose: impl Fn(&Secret<T>) -> &T) -> Self::Exposed<'_> {
        expose(self)
    }
}

impl<T: Serialize> SerializableSecret<T> for Option<Secret<T>> {
    type Exposed<'a>
        = Option<&'a T>
    where
        T: 'a;

    fn expose_via(&self, expose: impl Fn(&Secret<T>) -> &T) -> Self::Exposed<'_> {
        self.as_ref().map(expose)
    }
}

/// Exposes a [Secret] for serialization.
#[inline]
pub fn expose_secret<S: Serializer, T: Serialize>(
    secret: &impl SerializableSecret<T>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    secret
        .expose_via(Secret::expose_secret)
        .serialize(serializer)
}


/// Serialize a redacted [Secret] without exposing the contained data.
///
/// The secret will be serialized as its [`Debug`] output.
/// Since the data is redacted, it is not possible to deserialize data serialized in this way.
#[inline]
pub fn redact_secret<S: Serializer, T>(
    secret: &Secret<T>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.collect_str(&format_args!("{secret:?}"))
}