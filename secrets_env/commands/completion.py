import logging
import os
import sys

import click

from secrets_env.click import add_output_options, entrypoint


@entrypoint.command()
@click.argument("shell", type=click.Choice(["bash", "zsh", "fish"]), required=False)
@add_output_options
@click.pass_context
def completion(ctx: click.Context, shell: str):
    """Print shell completion script for this command.

    You can enable completion by running following command in your terminal:

       eval "$(secrets.env completion)"
    """
    logger = logging.getLogger(__name__)

    # get prog name
    prog_name = os.path.basename(sys.argv[0])
    if prog_name.lower().endswith(".py"):
        logger.warning(
            "Shell completion is not avaliable when invoked with `python -m` command"
        )

    # get shell
    if not shell:
        shell = os.path.basename(os.environ["SHELL"])
        logger.debug("Detect %s", shell)

    # print script
    import click.shell_completion

    rv = click.shell_completion.shell_complete(
        cli=ctx.command,
        ctx_args={},
        prog_name="secrets.env",
        complete_var="_COMPLETE",  # not really used
        instruction=f"{shell}_source",
    )

    sys.exit(rv)
