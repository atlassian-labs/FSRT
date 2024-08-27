// function reassign() {
//   let a = 3;
//   let b = 4;
//   a = 1;
// }

// function retimmed() {
//   return
// }

// function reassign2() {
//   let a = 3;
//   let b = 4;
//   a = 1;
//   return
// }

// function updatetest() {
//     let i = 0;
//     i++;
// }

// function updatetest2() {
//     let i = 0;
//     i = i + 1;
// }

// // function foo(a) {
// //   let b = a - 20;
// //   let c = b + 1;
// //   b = 10;
// //   return b * 10;
// // }

// // function reassign_expr() {
// //   let a = 4;
// //   let b = "7";
// //   b = "7" + a;
// //   let c = a + b;
// // }

// // w/ control flow
// function newfunc() {
//   let a = 3;
//   if (a > 2) {
//     a = 1;
//     let b = a;
//   }  
//   let c = a;
// }

// function newfunc2() {
//   let a = 3;
//   if (a > 2) {
//     a = 1;
//     let b = a;
//   } else {
//     a = 2;
//     let b = a;
//   }
//   let c = a;
// }

// function compnewfunc2() {
//   let a = Math.random();
//   let b = 0;
//   if (a >= 0.5) {
//     if (a > 0.5) {
//       a = a + 1;
//     } else {
//       a = a + 2;
//     }
//     b = a + 3;
//   }
//   let c = a;
// }

// function compnewfunc3() {
//   let a = Math.random();  // bb0
//   let b = 0;
//   if (a >= 0.5) {
//     if (a > 0.5) { // bb1
//       a = a + 1;   // bb4
//     } else {
//       a = a + 2;  // bb6
//     }
//     b = a + 3;  // bb5
//   } else {  // bb3
//     b = a + 4;
//   }
//   let c = a;  // bb2
// }

// function forloop() {
//   let a = 0;
//   for (let i = 0; i < 10; i = i + 1) {
//     a = a + i;
//   }
//   return a;
// }

// function whileloop() {
//   let a = 0;
//   let i = 0;
//   while (i < 10) {
//     a = a + i;  // bb3
//     i = i + 1;
//   }
//   return a;
// }

// function nestedforloop() {
//     let a = 0;
//     for (let i = 0; i < 10; i = i + 1) {
//       for (let j = 0; j < 10; j = j + 1) {
//         a = a + i + j;
//       }
//     }
//     return a;
// }

// function nestedwhileloop() {
//   let a = 0;
//   let i = 0;  // bb0
//   while (i < 10) {  // bb1
//     let j = 0;  // bb3
//     while (j < 10) {  // bb4
//       a = a + i + j;  // bb6
//       j = j + 1;
//     }
//     i = i + 1;  // bb5
//   }
//   return a;  // bb2
// }

// function whileandcond() {
//   let a = 0;
//   let i = 0;  // bb0
//   while (i < 10) {  // bb1
//     if (i > 5) {  // bb3
//       a = a + i;  // bb4
//     }
//     i++;  // bb5
//   }
//   return a;  // bb2
// }

// function whileandcond2() {
//   let a = 0;
//   let i = 0;  // bb0
//   while (i < 10) {  // bb1
//     if (i > 5) {  // bb3
//       a = a + 1;  // bb4
//     } else {
//       a = a + 2;  // bb6
//     }
//     i++;  // bb5
//   }
//   return a;  // bb2
// }

// function whileincond() {
//   let a = 0;
//   let b = Math.random();  // bb0
//   if (b < 0.5) {  // bb1
//     while (a < 2) {  // bb4
//       a = a + b;  // bb6
//     } 
//                   // bb5
//   } else {
//     a = 1;  // bb3
//   }
//   return a;  // bb2
// }
// function earlyretforloop() {
//     for (let i = 0; i < 10; i = i + 1) {
//         let a = Math.random();
//         if (a > 0.5) {
//             return;
//         }
//     }
// }

// function earlyretwhileloop() {
//     let i = 0;  // bb0
//     while (i < 10) {  // bb1
//       let a = Math.random();  // bb3
//       if (a > 0.5) {
//         return;  // bb4
//       }
//       i = i + 1;  // bb5
//     }
//     // bb2
// }

// // early return in `if` only
// function earlyret() {
//   let a = 0; 
//   if (a > 5) {  // bb0
//     a = 1;
//     return a;  // bb1
//   }
//   let b = 4;
//   return a;  // bb2
// }

// // early return in `else` only
// function earlyret2() {
//   let a = 0; 
//   if (a > 5) {
//     a = 1;
//   } else {
//     a = 2;
//     return a;
//     let c = 3;
//   }
//   let b = 4;
//   return a;
// }

// // early return in 'if' and 'else'
// function earlyret3() {
//   let a = 0; 
//   if (a > 5) {
//     a = 1;
//     return a;
//   } else {
//     a = 2;
//     return a;
//   }
//   let b = 4;  // a bb still gets created, it's just
//               // never jumped to. check if this is OK?
//               // assuming that this is how compilers work
//               // to detect unreachable code
//   return a;
// }

// // function earlyretloop() {
// //   let a = 0;
// //   let i = 0;
// //   while (i < 10) {
// //     if (i > 5) {
// //       return 1;
// //     }
// //     i = i + 1;
// //   }
// // }

////////////////////////////////////////////////////////////////
///////////////////// BREAK TEST FUNCTIONS /////////////////////
////////////////////////////////////////////////////////////////

// function simpleforloopbreak() {  // function kinda useless but testing a case
//     let a = 0;
//     for (let i = 0; i < 10; i = i + 1) {
//         a = a + 3;
//         break;
//         a = 2;
//     }
// }

function simplewhileloopbreak() {
    let a = 0;
    let i = 0;
    while (i < 10) {
        a = a + 3;
        break;
        // a = 2;
        // i = i + 1;
    }
    a = 3;  // added this chunk
}



// function whileloopbreak() {
//   let a = 0;
//   let i = 0;  // bb0
//   while (i < 10) {  // bb1
//     a = 7;
//     if (i > 5) {  // bb3
//       a = 1;  // bb4
//       break;
//     }
//     a = 3;  // bb5
//     i = i + 1;
//   }
//   return a;  // bb2
// }

// function forloopbreak() {
//     let a = 0;  // bb0
//     for (let i = 0; i < 10; i = i + 1) {  //bb 1
//         a = 7;
//         if (i > 5) {  // bb3
//             a = 1;  // bb4
//             break;
//         }
//         a = 3;  // bb5
//     }
//     return a;  // bb2
// }

// function forloopbreak3() {
//     let a = 0;
//     for (let i = 0; i < 10; i = i + 1) {
//         if (i === 5) {
//           a = 8;
//         } else {
//           break;
//         }
//         a = 3;
//     }
//     return a;
// }

// function whileloopbreak3() {
//     let a = 0;
//     let i = 0;
//     while (i < 10) {  // bb1
//         if (i === 5) {  // bb3
//           a = 8;  // bb4
//         } else {
//           break;  // bb6
//         }
//         a = 3;  // bb5
//         i = i + 1;
//     }
//     return a;  // bb2
// }

// function whileloopbreak2() {  // with two preds
//     let a = 0;
//     let i = 0;
//     while (i < 10) {
//       if (i > 5) {
//         a = 1;
//       }
//       break;
//       i = i + 1;
//     }
//     return a;
// }

// function forloopbreak2() {
//     let a = 0;
//     for (let i = 0; i < 10; i = i + 1) {  // bb1
//       if (i > 5) {  // bb3
//         a = 1;  // bb4
//       }
//       break;  // bb5
//     }
//     return a;  // bb2
// }

// function labelcheck() {
//     let a = 0;
//     single:
//     for (let i = 0; i < 10; i = i + 1) {
//         if (i === 5) {
//             break single;
//         }
//         a = 2;
//         break;
//     }
//     return a;
// }

// function twopredbreak() {
//     let a = 0;
//     for (let i = 0; i < 10; i = i + 1) {
//         if (i === 5) {
//             a = 2;  // bb4
//         }
//         break;  // bb5
//     }
//     return a;
// }

// break that comes after an if, inside a for
// preds will show two - one from body of stmt::if, the other the cond of stmt::if
// get the block who's term is term::if (that's the cond) -> keep recursing till get to the cond of a loop
// grab the alt of that loop
// function twopredbreak2() {
//     let a = 0;
//     let i = 0;
//     for (; i < 10; i = i + 1) {
//         if (i === 5) {  // bb3
//             a = 2;  // bb4
//         }
//         break;  // bb5
//     }
//     return i;  // bb2
// }

// function whileloopbreak() {
//     let a = 0;
//     let i = 0;
//     while (i < 10) {
//         if (i === 5) {
//             break;
//         }
//         a = 2;
//         i = i + 1;
//     }
//     return a;
// }

// function dowhilebreak() {
//     let i = 0;  //bb0
//     do {  // bb3
//         if (i === 3) {
//             break;  // bb4
//         }
//         i = i + 1;  // bb5
//     } while ( i < 10);  // bb1
//     let a = 2;  // bb2
// }

// // ignore below for now
// // function nestedforloop() {
// //   let a = 0;  // bb0
// //   for (let i = 0; i < 10; i++) {  // i = 0 is in bb0; cond in bb1; i++ in bb4
// //     for (let j = 0; j < 10; j++) {  // j = 0 in bb3; cond in bb4
// //       a = a + i + j;  //bb6
// //     }
// //     let b = 3;
// //   }
// //   return a;  // bb2
// // }
