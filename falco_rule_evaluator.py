"""
Description: Shunting yard parsing infix expressions (rule condition format) into a tree and evaluates it
TODO: Support other operators

Referenced: https://tomekkorbak.com/2020/03/25/implementing-shunting-yard-parsing/
"""
from dataclasses import dataclass

class Node:
    """
    Defining node class for the expression tree
    """
    def __init__(self, data: str, left: 'Node' = None, right: 'Node' = None) -> 'Node':
        self.data = data
        self.left = left
        self.right = right

    def leaf_check(self) -> bool:
        """
        Check if node is a leaf (operand)
        """
        return self.left is None and self.right is None

def eval_to_bool(data, fes: dict) -> bool:
    """
    Evaluates a leaf node and returns a boolean values
    for each sysdig event the condition is compared with.

    :param data: token data from node
    :param fes: fake sysdig event sequence dictionary
    """
    return data[0] in fes and data[1] == fes[data[0]]

@dataclass
class Tree:
    """
    Defining tree class for the expression tree construction
    """
    root: Node

    @classmethod
    def construct_tree(cls, tokens: str) -> 'Tree':
        """
        Constructs expression tree from given infix notation

        :params tokens: list of infix expression tokens
        """
        operator_stack: list[str] = []
        operand_stack: list[Node] = []

        for token in tokens:

            # operands
            if isinstance(token, tuple):
                operand_stack.append(
                    Node(
                        token,
                        left=None,
                        right=None
                        )
                    )
                    
            # check logical operator precedence
            elif token == "or" and len(operator_stack) > 0 and operator_stack[-1] == "and":
                right = operand_stack.pop()
                operator = operator_stack.pop()
                left = operand_stack.pop()
                operand_stack.append(
                    Node(
                        operator,
                        left=left,
                        right=right
                        )
                    )
                operator_stack.append(token)

            # parsing parentheses
            elif token == ")":
                while len(operator_stack) > 0 and operator_stack[-1] != "(":
                    right = operand_stack.pop()
                    operator = operator_stack.pop()
                    left = operand_stack.pop()
                    operand_stack.append(
                        Node(
                            operator,
                            left=left,
                            right=right
                        )
                    )
                operator_stack.pop()

            else:
                operator_stack.append(token)
    
        # empty the stack
        while len(operator_stack) > 0:
            right = operand_stack.pop()
            operator = operator_stack.pop()
            left = operand_stack.pop()
            operand_stack.append(
                Node(
                    operator,
                    left=left,
                    right=right
                    )
                )
        
        # return the tree
        return cls(root=operand_stack.pop())

    def evaluate(self, fes, node: Node = None):
        """
        Recursive method for evaluating the tree's nodes

        :param fes: fake Sysdig event sequence list
        :param node: node from expression tree
        """
        node = node or self.root
        
        # lambda expression to evaluate logical operators
        process = {"and": (lambda x, y: x and y), "or": (lambda x, y: x or y)}

        if node is None:
            return False

        if node.leaf_check():
            return eval_to_bool(node.data, fes)
        
        x = self.evaluate(fes, node.left)
        y = self.evaluate(fes, node.right)
            
        return process[node.data](x, y)

def main():
    """
    Main function
    """

    fake_event_sequences = [
        [{"evt.arg.flags" : "O_TRUNC", "fd.filename": ".bashrc"}],
        [{"evt.arg.flags" : "O_APPEND", "evt.type" : "openat", "evt.is_open" : "true"}, {"evt.type":"hello"}],
        [{"evt.type":"hello", "evt.arg.flags":"O_APPEND"}, {"evt.type":"blah"}],
        [{"evt.type":"blah", "evt.arg.flags" : "O_TRUNC"}]
    ]

    # transform operands to tuple for matching with dictionary items
    to_tuple = lambda x : (x.split("=")[0], x.split("=")[1])

    # sample Falco rule conditions
    s = "( evt.type=blah or evt.arg.flags=O_APPEND ) and ( evt.arg.flags=O_TRUNC or fd.filename=.bashrc )"
    
    # tokenizing
    test = [to_tuple(x) if "=" in x else x for x in s.split(" ")]
    
    # construct tree from condition tokens
    tree = Tree.construct_tree(test)
    print([tree.evaluate(x) for fes in fake_event_sequences for x in fes])

if __name__ == '__main__':
    main()