// function reassign() {
//   let a = 3;
//   let b = 4;
//   a = 1;
// }

// function foo(a) {
//   let b = a - 20;
//   let c = b + 1;
//   b = 10;
//   return b * 10;
// }

// function reassign_expr() {
//   let a = 4;
//   let b = "7";
//   b = "7" + a;
//   let c = a + b;
// }

// w/ control flow
function newfunc() {
  let a = 3;
  if (a > 2) {
    a = 1;
    let b = a;
  }  
  let c = a;
}

function compnewfunc2() {
  let a = Math.random();
  let b = 0;
  if (a >= 0.5) {
    if (a > 0.5) {
      a = a + 1;
    } else {
      a = a + 2;
    }
    b = a + 3;
  }
  let c = a;
}

function compnewfunc3() {
  let a = Math.random();  // bb0
  let b = 0;
  if (a >= 0.5) {
    if (a > 0.5) { // bb1
      a = a + 1;   // bb4
    } else {
      a = a + 2;  // bb6
    }
    b = a + 3;  // bb5
  } else {  // bb3
    b = a + 4;
  }
  let c = a;  // bb2
}