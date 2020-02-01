defmodule Stein.MFA.OneTimePassword.Token do
  @moduledoc """
  Stein.MFA.OneTimePassword.Token represent a generated 6 (or 8) digit value from
  a Stein.MFA.OneTimePassword.Secret. It is the literal "one time password"
  for authentication

  The usage of "token" is mirroring the underlying library, :pot
  """

  alias Stein.MFA.OneTimePassword.Secret

  @type token_value :: binary()

  @type hotp_t :: %__MODULE__{
          value: token_value(),
          secret: Secret.hotp_t()
        }

  @typedoc """
    totp_t represents a token generated for time based validation from an appropriate
    secret.
  """
  @type totp_t :: %__MODULE__{
          value: token_value(),
          secret: Secret.totp_t(),
          time_tolerance: non_neg_integer()
        }

  @enforce_keys [:value, :secret]
  defstruct [:value, :secret, :time_tolerance]

  @secret_atom_to_erlang_crypto_atom %{
    :SHA1 => :sha,
    :SHA256 => :sha256,
    :SHA512 => :sha512
  }

  @doc """
    Generates a token from the given secret

    in the resulting struct, `value` is the token value (e.g. "123456")

    `secret` is the secret to use to validate against.
    For a Time-based token: this will be identical to the one passed in.
    For an HMAC-based token: this is the passed in secret with the counter incremented
  """

  @spec generate(Secret.totp_t()) :: totp_t()
  def generate(%Secret{type: :totp} = s) do
    %__MODULE__{
      value:
        :pot.totp(
          s.secret_value,
          digest_method: @secret_atom_to_erlang_crypto_atom[s.algorithm],
          token_length: s.digits,
          interval_length: s.period
        ),
      secret: s
    }
  end

  @spec generate(Secret.hotp_t()) :: hotp_t()
  def generate(%Secret{type: :hotp} = s) do
    s = %Secret{s | counter: s.counter + 1}

    %__MODULE__{
      value:
        :pot.hotp(
          s.secret_value,
          s.counter,
          digest_method: @secret_atom_to_erlang_crypto_atom[s.algorithm],
          token_length: s.digits
        ),
      secret: s
    }
  end

  @doc """
   Validates the given token against its embeded secret.

  `time_tolerance` is an integer, n >= 0, such that the the previous n (and next n) tokens,
    rolling over every s.period seconds will,
    validate as well as the "current" one when validation is performed. This is to account
    for both clock drift between people's phones and the servers, as well as, you know, typing slow

    Unsurprisingly, this argument is ignored for HMAC-based tokens
  """
  def validate(oken, time_tolerance \\ 0)

  @spec validate(hotp_t()) :: boolean()
  def validate(%__MODULE__{value: v, secret: %Secret{type: :hotp} = s}, _time_tolerance) do
    :pot.valid_hotp(v, s.secret_value,
      digest_method: @secret_atom_to_erlang_crypto_atom[s.algorithm],
      last: s.counter - 1,
      token_length: s.digits
    )
  end

  @spec validate(totp_t(), non_neg_integer()) :: boolean()

  def validate(%__MODULE__{value: v, secret: %Secret{type: :totp} = s}, time_tolerance) do
    :pot.valid_totp(v, s.secret_value,
      digest_method: @secret_atom_to_erlang_crypto_atom[s.algorithm],
      token_length: s.digits,
      window: time_tolerance,
      interval_length: s.period
    )
  end
end
