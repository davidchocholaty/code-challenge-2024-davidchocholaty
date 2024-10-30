class Stack:
    def __init__(self):
        # Initialize an empty list to hold stack elements
        self._stack = []

    def push(self, item):
        # Add an item to the top of the stack
        self._stack.append(item)

    def pop(self):
        # Remove and return the top item from the stack
        # Raise an exception if the stack is empty
        if not self.is_empty():
            return self._stack.pop()
        else:
            raise IndexError("pop from empty stack")

    def peek(self):
        # Return the top item from the stack without removing it
        # Raise an exception if the stack is empty
        if not self.is_empty():
            return self._stack[-1]
        else:
            raise IndexError("peek from empty stack")

    def is_empty(self):
        # Return True if the stack is empty, False otherwise
        return len(self._stack) == 0

    def size(self):
        # Return the number of items in the stack
        return len(self._stack)

    def __repr__(self):
        # Return a string representation of the stack
        return f"Stack({self._stack})"
