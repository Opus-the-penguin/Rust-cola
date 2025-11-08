//! ⚠️ SECURITY SCANNER NOTICE ⚠️
//!
//! This crate contains INTENTIONAL security vulnerabilities for testing RUSTCOLA041.
//! DO NOT use these patterns in production code.
//!
//! codeql[rust/panic-in-future]: Test examples for unwrap/panic in Future::poll detection

// NOSEC: This file contains test patterns for security scanners

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

/// BAD: unwrap() in poll can stall the executor
pub struct BadUnwrapFuture {
    value: Option<i32>,
}

impl Future for BadUnwrapFuture {
    type Output = i32;

    fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        // NOSEC - unwrap() in poll! This panics if value is None, stalling the executor
        let result = self.value.unwrap();
        Poll::Ready(result)
    }
}

/// BAD: expect() in poll can stall the executor  
pub struct BadExpectFuture {
    data: Result<String, ()>,
}

impl Future for BadExpectFuture {
    type Output = String;

    fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        // NOSEC - expect() in poll! This panics on Err, stalling the executor
        let result = self.data.as_ref().expect("data must be Ok");
        Poll::Ready(result.clone())
    }
}

/// BAD: panic! in poll can stall the executor
pub struct BadPanicFuture {
    ready: bool,
}

impl Future for BadPanicFuture {
    type Output = ();

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        if !self.ready {
            // NOSEC - panic! in poll! This stalls the executor
            panic!("not ready yet!");
        }
        Poll::Ready(())
    }
}

/// GOOD: Use match to handle None/Err properly
pub struct GoodMatchFuture {
    value: Option<i32>,
}

impl Future for GoodMatchFuture {
    type Output = Result<i32, ()>;

    fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.value {
            Some(v) => Poll::Ready(Ok(v)),
            None => Poll::Ready(Err(())),
        }
    }
}

/// GOOD: Propagate errors via Poll::Ready(Err(...))
pub struct GoodErrorPropagationFuture {
    data: Result<String, String>,
}

impl Future for GoodErrorPropagationFuture {
    type Output = Result<String, String>;

    fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Ready(self.data.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_futures_compile() {
        // Just verify the types are correct
        let _bad1 = BadUnwrapFuture { value: Some(42) };
        let _bad2 = BadExpectFuture { data: Ok("test".to_string()) };
        let _bad3 = BadPanicFuture { ready: true };
        let _good1 = GoodMatchFuture { value: Some(42) };
        let _good2 = GoodErrorPropagationFuture { data: Ok("test".to_string()) };
    }
}
