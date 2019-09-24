import os
import numpy as np
from itertools import combinations
from hashlib import md5
import Crypto
from Crypto.Util import number
from DynaSwapApp.models import Roles, Users, UsersRoles


"""
'A Practical and Flexible Key Management Mechanism
For Trusted Collaborative Computing'
X. Zou, et. al.
https://ieeexplore.ieee.org/document/4509697
"""


class ACP:
    def __init__(self, node, secret):
        """
        Constructor for ACP.
        Args:
            secret(string): the secret information encapsulated in ACP
        Returns:
            N/A
        """
        self.node = node
        self.z = hex(number.getRandomInteger(128))
        self.q = hex(number.getPrime(128))
        self.__K = secret
        self.coefficients = []

        # Make sure key value is smaller than prime used for modulo
        while int(secret, 16) >= int(self.q, 16):
            self.q = hex(number.getPrime(128))

    def get_coefficients(self):
        """
        Derive the list of coefficients of the ACP.
        Args:
            users(list of user objects): list of users in the node used for computing ACP
        Returns:
            lists of coefficients
        """
        SIDs = []
        node_obj = Roles.objects.get(role=self.node)
        for user in UserRoles.objects.filter(role=node_obj):
            user_obj = user.user_id
            message = user_obj.get_SID() + self.z
            SIDs.append(-int(md5(message.encode("utf-8")).hexdigest(), 16))
        coefficients = []
        coefficients.append(1)
        iq = int(self.q, 16)
        for i in range(0, len(SIDs)):
            coefficients.append(0)
            for j in range(1, len(coefficients)):
                coefficients[len(coefficients) - j] = coefficients[len(coefficients) - j] + coefficients[len(coefficients) - j - 1] * SIDs[i] % iq

        coefficients[-1] = (coefficients[-1] +
                            int(self.__K, 16)) % iq
        self.coefficients = coefficients
        return coefficients

    def evaluate_polynomial(self, SID):
        """
        Compute the secret from ACP, later on should be computed on client side and should provide the z and q.
        Args:
            SID(string): user's secret SID
        Returns:
            the secret information in the ACP
        """
        message = SID + self.z
        x = int(md5(message.encode("utf-8")).hexdigest(), 16)
        cur = 1
        res = 0
        iq = int(self.q, 16)
        for i in range(0, len(self.coefficients)):
            res = (res + cur * self.coefficients[len(self.coefficients) - 1 - i] % iq) % iq
            cur = cur * x % iq
        return hex(res)[2:]