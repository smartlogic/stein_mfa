defmodule Stein.MFA.OneTimePassword.Secret do
  @moduledoc """
  `Stein.MFA.OneTimePassword.Secret` contains the struct and functions for generation of `:pot` useful secret keys
  and Google Authenticator compatible (QR-) presentable urls for them.
  """

  @typedoc "Secret type; totp or hotp"
  @type stype :: :totp | :hotp
  @typedoc "Hash algorithim used"
  @type algorithm :: :SHA1 | :SHA256 | :SHA512
  @typedoc "How many digits to generate in a token"
  @type digits :: 6 | 8

  @typedoc "Generically a OTP secret, of either type. May or may not be valid "
  @type t :: %__MODULE__{
          type: stype,
          label: String.t(),
          secret_value: binary,
          issuer: String.t() | nil,
          algorithm: algorithm,
          digits: digits
        }

  @typedoc "a Time-based OTP secret, with a valid period"
  @type totp_t :: %__MODULE__{
          type: :totp,
          label: String.t(),
          secret_value: binary,
          issuer: String.t() | nil,
          algorithm: algorithm,
          digits: digits,
          period: pos_integer()
        }

  @typedoc "an HMAC-based OTP secret, with a valid counter"
  @type hotp_t :: %__MODULE__{
          type: :hotp,
          label: String.t(),
          secret_value: binary,
          issuer: String.t() | nil,
          algorithm: algorithm,
          digits: digits,
          counter: non_neg_integer()
        }

  @enforce_keys [:label, :secret_value]
  defstruct(
    type: :totp,
    label: nil,
    secret_value: nil,
    issuer: nil,
    algorithm: :SHA1,
    digits: 6,
    counter: nil,
    period: nil
  )

  @doc "Creates a new Time-based secret"
  @spec new_totp(String.t(),
          issuer: String.t(),
          bits: pos_integer(),
          algorithm: algorithm,
          period: pos_integer()
        ) ::
          totp_t()
  def new_totp(label, opts \\ []) do
    secret_value = generate_secret(opts[:bits] || 160)

    %__MODULE__{
      type: :totp,
      label: label,
      secret_value: secret_value,

      # overrideables
      issuer: opts[:issuer] || default_issuer(),
      algorithm: opts[:algorithim] || :SHA1,
      period: opts[:period] || 30
    }
  end

  @doc "Creates a new HMAC/counter-based secret"
  @spec new_hotp(String.t(),
          issuer: String.t(),
          bits: pos_integer(),
          initial_counter: non_neg_integer()
        ) :: hotp_t()
  def new_hotp(label, opts \\ []) do
    secret_value = generate_secret(opts[:bits] || 160)

    %__MODULE__{
      type: :hotp,
      label: label,
      secret_value: secret_value,

      # overrideables
      issuer: opts[:issuer] || default_issuer(),
      algorithm: opts[:algorithim] || :SHA1,
      counter: opts[:initial_counter] || 0
    }
  end

  # Returns the configed issuer or nil. Can be overrided with issuer keyword in each of above
  defp default_issuer, do: Application.get_env(:stein_mfa, :one_time_password_issuer)

  @spec generate_secret(pos_integer()) :: binary
  # Generates a base32 encoded shared secret (K) of the given number of bits to the closest byte.
  # Minimum of 128 per https://tools.ietf.org/html/rfc4226#section-4 R6
  defp generate_secret(bits) when bits > 128 do
    :crypto.strong_rand_bytes(div(bits, 8)) |> :pot_base32.encode()
  end

  @spec enrollment_url(t) :: String.t()

  @doc """
  Generates a Google Authenticator format url per https://github.com/google/google-authenticator/wiki/Key-Uri-Format
  """
  def enrollment_url(%__MODULE__{} = s) do
    "otpauth://#{s.type}/#{URI.encode(label_maybe_with_issuer(s))}?" <> paramaters(s)
  end

  defp label_maybe_with_issuer(%__MODULE__{issuer: nil} = s), do: s.label
  defp label_maybe_with_issuer(%__MODULE__{} = s), do: "#{s.issuer}:#{s.label}"

  @spec paramaters(hotp_t) :: String.t()
  defp paramaters(%__MODULE__{type: :hotp, counter: c} = s) when not is_nil(c) do
    _parameters(s, :counter)
  end

  @spec paramaters(totp_t) :: String.t()
  defp paramaters(%__MODULE__{type: :totp, period: p} = s) when not is_nil(p) do
    _parameters(s, :period)
  end

  defp paramaters(%__MODULE__{type: :totp}) do
    raise ArgumentError, "TOTP must have period"
  end

  defp paramaters(%__MODULE__{type: :hotp}) do
    raise ArgumentError, "HOTP must have counter"
  end

  defp _parameters(s, key) do
    Map.take(s, [:issuer, :algorithm, :digits, key])
    |> Map.put("secret", s.secret_value)
    |> Enum.filter(&(!is_nil(elem(&1, 1))))
    |> URI.encode_query()
  end
end
