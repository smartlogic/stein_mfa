defmodule Stein.MFA.OneTimePassword.Secret do
  @moduledoc """
  `Stein.MFA.OneTimePassword.Secret` contains the struct and functions for generation of `:pot` useful secret keys
  and Google Authenticator compatible (QR-) presentable urls for them.
  """

  @type secret_type :: :totp | :hotp
  @type algorithm :: :SHA1 | :SHA256 | :SHA512

  @enforce_keys [:label, :secret_value]
  defstruct(
    type: :totp,
    algorithm: :sha1,
    label: nil,
    secret_value: nil,
    issuer: nil,
    counter: nil,
    period: nil
  )

  @typedoc "Generically a OTP secret, of either type. May or may not be valid "
  @type t :: %__MODULE__{
          type: secret_type,
          algorithm: algorithm,
          secret_value: :pot.secret(),
          label: String.t(),
          issuer: String.t() | nil
        }

  @typedoc "a Time-based OTP secret, with a valid period"
  @type totp_t :: %__MODULE__{
          type: :totp,
          algorithm: algorithm,
          secret_value: :pot.secret(),
          label: String.t(),
          issuer: String.t() | nil,
          period: pos_integer()
        }

  @typedoc "an HMAC-based OTP secret, with a valid counter"
  @type hotp_t :: %__MODULE__{
          type: :hotp,
          algorithm: algorithm,
          secret_value: :pot.secret(),
          label: String.t(),
          issuer: String.t() | nil,
          counter: non_neg_integer()
        }

  def new_totp(label, opts) do
    secret_value = generate_secret(opts[:bits] || 160)

    %__MODULE__{
      type: :totp,
      secret_value: secret_value,
      label: label,
      period: opts[:period] || 30
    }
  end

  def new_hotp(label, issuer, opts) do
  end

  @spec generate_secret(pos_integer()) :: :pot.secret()
  defp generate_secret(bits) when bits > 128 do
  end

  @doc """
  Generates a Google Authenticator format url per https://github.com/google/google-authenticator/wiki/Key-Uri-Format)
  """
  def enrollment_url(%__MODULE__{} = s) do
    "otpauth://#{s.type}/#{label_maybe_with_issuer(s)}?"
  end

  defp label_maybe_with_issuer(%__MODULE__{issuer: nil} = s), do: s.label
  defp label_maybe_with_issuer(%__MODULE__{} = s), do: "#{s.issuer}:#{s.label}"

  defp paramaters(%__MODULE__{type: :hotp, counter: c} = s) when not is_nil(c) do
    ""
  end

  defp paramaters(%__MODULE__{type: :totp, period: p} = s) when not is_nil(p) do
    ""
  end

  defp paramaters(%__MODULE__{type: :totp}) do
    raise ArgumentError, "TOTP must have period"
  end

  defp paramaters(%__MODULE__{type: :hotp}) do
    raise ArgumentError, "HOTP must have counter"
  end
end
