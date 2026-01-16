#include <python3.11/Python.h>
#include <python3.11/boolobject.h>
#include <python3.11/object.h>
#include <stddef.h>

typedef struct {
  Py_ssize_t ob_size;
  char obj[];
} _lockobject_data;

typedef struct {
  PyObject_HEAD
  _lockobject_data *ob_data;
} PyLockObject;

static PyObject *lock_new(PyTypeObject *type, PyObject *args, PyObject *kwargs);
static int lock_init(PyObject *self, PyObject *args, PyObject *kwargs);
static PyObject *lock_repr(PyObject *self);

static PyObject *lock_unlock(PyObject *self, PyObject *args);
void xor_inplace(char *buf, char *key, Py_ssize_t buf_size, Py_ssize_t key_size);

const char scam_msg[] = "PLEASE TRANSFER 100,200,300,400,600,700,100,000,34 BITCOIN TO WALLET ADDRESS 0xdeadbeefcafebabe THANK YOU!!";

PyDoc_STRVAR(lock_doc, "lock(key, obj) -> lock\n\
  \n\
  The lock object encrypts an object, preventing any access to the object.\n\
  The object can subsequently be accessed via lock.unlock, which removes the lock permanently.");

PyMethodDef lock_methods[] = {
  {
    .ml_name = "unlock",
    .ml_meth = lock_unlock,
    .ml_flags = METH_VARARGS,
  },
  {NULL}
};

PyTypeObject PyLock_Type = {
    PyVarObject_HEAD_INIT(&PyType_Type, 0)
    .tp_name = "lock",
    .tp_doc = lock_doc,
    .tp_repr = lock_repr,
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_basicsize = offsetof(PyLockObject, ob_data),
    .tp_itemsize = 0,
    .tp_new = lock_new,
    .tp_free = PyObject_Free,
    .tp_methods = lock_methods,
};

PyModuleDef money_def = {
    .m_name = "money",
};

// expected arguments: (key, object)
PyObject *lock_new(PyTypeObject *type, PyObject *args, PyObject *kwargs) {
  PyLockObject *lock = NULL;
  PyObject *obj = NULL;
  PyBytesObject *key = NULL;
  Py_ssize_t size = 0;
  Py_ssize_t key_size = 0;
  _lockobject_data *buffer = NULL;

  if (!PyTuple_Check(args) || PyTuple_GET_SIZE(args) != 2) {
    PyErr_SetString(PyExc_ValueError, "expected 2 arguments");
    return NULL;
  }

  obj = PyTuple_GetItem(args, 1);

  // get the object size
  if (obj->ob_type->tp_basicsize == 0) {
    size = obj->ob_type->tp_basicsize;
  } else {
    size = obj->ob_type->tp_basicsize
      + _PyVarObject_CAST(obj)->ob_size * obj->ob_type->tp_itemsize;
  }
  
  key = (PyBytesObject *)PyTuple_GetItem(args, 0);
  if (!PyBytes_Check(key)) {
    PyErr_SetString(PyExc_TypeError, "expected bytestring for key");
    return NULL;
  }
  if ((key_size = PyBytes_GET_SIZE(key)) == 0) {
    PyErr_SetString(PyExc_TypeError, "key length cannot be zero");
    return NULL;
  }

  // store the object
  buffer = PyMem_Malloc(sizeof(_lockobject_data) + size + key_size);
  if (buffer == NULL) {
    PyErr_NoMemory();
    return NULL;
  }
  buffer->ob_size = size;

  // place the key at the end of the object
  // and encrypt the entire (object + key) buffer
  memcpy(&buffer->obj[size], key->ob_sval, key_size);
  memcpy(buffer->obj, obj, buffer->ob_size);
  xor_inplace(buffer->obj, key->ob_sval, buffer->ob_size + key_size, key_size);

  // replace the old object with a lock object
  lock = (PyLockObject *)obj;
  lock->ob_base.ob_type = &PyLock_Type;
  lock->ob_data = buffer;

  // prevent gc from killing our object
  Py_INCREF(lock);

  return (PyObject *)lock;
}

PyObject *lock_repr(PyObject *self) {
  PyLockObject *lock = (PyLockObject *)self;

  if (self->ob_type != &PyLock_Type) {
    PyErr_SetString(PyExc_TypeError, "expected lock for self");
    return NULL;
  }

  return PyUnicode_FromString(scam_msg);
}

// on successful decryption, the lock buffer will be freed, and the lock object transformed to the target object
// if unsuccessful, both the lock object and buffer will remain alive
PyObject *lock_unlock(PyObject *self, PyObject *args) {
  PyLockObject *lock = NULL;
  PyBytesObject *key = NULL;
  char *buffer = NULL;
  _lockobject_data *data = NULL;
  PyObject *new_obj = NULL;
  Py_ssize_t key_size = 0;

  if (self->ob_type != &PyLock_Type) {
    PyErr_SetString(PyExc_TypeError, "expected lock for self");
    goto exit;
  } else if (!PyTuple_Check(args) || PyTuple_GET_SIZE(args) != 1) {
    PyErr_SetString(PyExc_ValueError, "expected 1 argument");
    goto exit;
  } else if (!PyBytes_Check(key = (PyBytesObject *)PyTuple_GetItem(args, 0))) {
    PyErr_SetString(PyExc_TypeError, "expected bytestring for key");
    goto exit;
  } else if ((key_size = PyBytes_GET_SIZE(key)) == 0) {
    PyErr_SetString(PyExc_TypeError, "key length cannot be zero");
    goto exit;
  }

  lock = (PyLockObject *)self;
  data = lock->ob_data;

  // allocate buffer for object + canary
  buffer = PyMem_Malloc(data->ob_size + key_size);
  if (buffer == NULL) {
    PyErr_NoMemory();
    goto exit;
  }

  memcpy(buffer, data->obj, data->ob_size + key_size);
  xor_inplace(buffer, key->ob_sval, data->ob_size + key_size, key_size);
  // if decryption is successful, key should be in memory right after the object
  if (memcmp(&buffer[data->ob_size], key->ob_sval, key_size)) {
    PyErr_Format(PyExc_ValueError, "incorrect key (canary value is %p)", buffer[lock->ob_data->ob_size]);
    goto exit;
  }

  // on successful decryption, replace lock object with the desired object
  new_obj = (PyObject *)lock;
  memcpy(new_obj, buffer, data->ob_size);
  // and destroy the backing buffer
  PyMem_Free(data);

exit:
  if (buffer != NULL) PyMem_Free(buffer);
  return new_obj;
}

void xor_inplace(char *buf, char *key, Py_ssize_t buf_size, Py_ssize_t key_size) {
  Py_ssize_t key_off = 0;
  for (Py_ssize_t i = 0; i < buf_size; i++) {
    buf[i] = buf[i] ^ key[key_off++ % key_size];
  }
}

PyObject *PyInit_money() {
  PyObject *money_module = PyModule_Create(&money_def);
  PyType_Ready(&PyLock_Type);
  Py_INCREF(&PyLock_Type);
  PyModule_AddObject(money_module, "lock", (PyObject *)&PyLock_Type);
  return money_module;
}
