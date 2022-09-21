#[macro_export]
macro_rules! create_newtype {
    ($vis:vis struct $ident:ident ( $ty:ty );) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        $vis struct $ident($ty);

        impl ::core::convert::From<usize> for $ident {
            fn from(n: usize) -> $ident {
                $ident(n as $ty)
            }
        }

        impl ::core::convert::From<$ident> for usize {
            fn from(id: $ident) -> usize {
                id.0 as usize
            }
        }
    };
}
