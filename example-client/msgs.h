#include <stddef.h>

const char MSG0[3] = {\
  "123"
};

const uint8_t MSG1[5] = {\
  152, 34, 78, 92, 201
};

const uint8_t* MSGS[2] = {\
  (uint8_t*) MSG0, MSG1
};

const size_t MSG_LENS[2] = {\
  3, 5
};
