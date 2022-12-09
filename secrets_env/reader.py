import abc
from typing import Dict, Union


class ReaderBase(abc.ABC):
    """Abstract base class for secret reader. All secret provider must implement
    this interface.
    """

    @abc.abstractmethod
    def get(self, spec: Union[Dict[str, str], str]) -> str:
        """Get secret value.

        Parameters
        ----------
        spec : dict | str
            Raw input from config file.

            It should be :py:class:`dict` in most cases; or :py:class:`str` if
            this provider accepts shortcut.

        Return
        ------
        The secret value.

        Raises
        ------
        ~secrets_env.exceptions.ConfigError
            The path dict is malformed.
        ~secrets_env.exceptions.SecretNotFound
            The path dict is correct but the secret not exists.

        Note
        ----
        Key ``source`` is preserved in ``spec`` dictionary.
        """
