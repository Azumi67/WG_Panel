class RuntimeContext:


    def __init__(self, namespace):
        object.__setattr__(self, 'namespace', namespace)

    def __getattr__(self, name):
        try:
            return self.namespace[name]
        except KeyError:
            raise NameError(f"Panel runtime dependency {name!r} is not initialized") from None

    def __setattr__(self, name, value):
        self.namespace[name] = value

    def __delattr__(self, name):
        del self.namespace[name]
