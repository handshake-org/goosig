'use strict';

// https://svn.python.org/projects/python/trunk/Lib/heapq.py

function _siftdown(heap, startpos, pos) {
  const newitem = heap[pos];

  while (pos > startpos) {
    const parentpos = (pos - 1) >>> 1;
    const parent = heap[parentpos];

    if (newitem[0] < parent[0]) {
      heap[pos] = parent;
      pos = parentpos;
      continue;
    }

    break;
  }

  heap[pos] = newitem;
}

function _siftup(heap, pos) {
  const endpos = heap.length;
  const startpos = pos;
  const newitem = heap[pos];

  let childpos = 2 * pos + 1;

  while (childpos < endpos) {
    const rightpos = childpos + 1;
    if (rightpos < endpos && !(heap[childpos][0] < heap[rightpos][0]))
      childpos = rightpos;
    heap[pos] = heap[childpos];
    pos = childpos;
    childpos = 2 * pos + 1;
  }

  heap[pos] = newitem;
  _siftdown(heap, startpos, pos);
}

function heapreplace(heap, item) {
  const returnitem = heap[0];
  heap[0] = item;
  _siftup(heap, 0);
  return returnitem;
}

function heappush(heap, item) {
  heap.push(item);
  _siftdown(heap, 0, heap.length - 1);
}

exports.heapreplace = heapreplace;
exports.heappush = heappush;
