mod infrai_rest;
mod learner_audit;

use learner_audit::{CourseDelivery, KeyIncident};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

fn main() {
    let rest = match infrai_rest::InfraiRest::from_environment() { Ok(value) => value, Err(error) => { eprintln!("configuration error: {:?}", error); return; } };
    let delivery = CourseDelivery { course: "algebra-1".to_string(), learner: "learner-42".to_string(), deadline_passed: true };
    match block_on(KeyIncident::new(&rest).rotate_and_audit(&delivery)) {
        Ok(decision) => println!("{}: {:?}", delivery.course, decision),
        Err(error) => eprintln!("incident request failed: {:?}", error),
    }
}

fn block_on<F: Future>(future: F) -> F::Output {
    fn no_op(_: *const ()) {}
    fn clone(_: *const ()) -> RawWaker { RawWaker::new(std::ptr::null(), &VTABLE) }
    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, no_op, no_op, no_op);
    let waker = unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) };
    let mut context = Context::from_waker(&waker);
    let mut future = Box::pin(future);
    loop { match Pin::as_mut(&mut future).poll(&mut context) { Poll::Ready(value) => return value, Poll::Pending => std::thread::yield_now() } }
}
