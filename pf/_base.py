"""Base class for all PF-related objects"""


__all__ = ['PFObject']


class PFObject(object):
    """Base class for wrapper objects around Structures."""

    _struct_type = None

    def __init__(self, obj=None, **kwargs):
        """Check the type of obj and initialize instance attributes."""

        if self._struct_type is not None and isinstance(obj, self._struct_type):
            self._from_struct(obj)
        elif isinstance(obj, basestring):
            self._from_string(obj)
        
        self._from_kwargs(**kwargs)

    def _from_struct(self, struct):
        raise NotImplementedError()

    def _from_string(self, line):
        raise NotImplementedError()

    def _from_kwargs(self, **kwargs):
        for k, v in kwargs.iteritems():
            if hasattr(self, k):
                setattr(self, k, v)
            else:
                raise AttributeError("Unexpected argument: {}".format(k))

    def _to_struct(self):
        raise NotImplementedError()
    
    def _to_string(self):
        raise NotImplementedError()

    def __str__(self):
        return self._to_string()
