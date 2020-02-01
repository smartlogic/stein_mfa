defmodule Stein.MFA do
  @moduledoc """
  `Stein.MFA` provides a helper for `Stein.Accounts` to facilitate use of 2nd factor auth in Stein based apps.
  """

  alias Stein.MFA.OneTimePassword.{Secret, Token}

  @doc "Creates a Stein.MFA.OneTimePassword.Secret of `type` for a given user"

  #TODO?: Indirect the secret object to support WebAuthn and/or U2F through this
  # interface, using only type difference. Though like ... the whole enrollment is kinda different

  def create_secret_for_user(email, type \\ :totp)

  @spec create_secret_for_user(Stein.Accounts.email(), :totp) :: Secret.totp_t()
  def create_secret_for_user(email, :totp), do: Secret.new_totp(email)

  @spec create_secret_for_user(Stein.Accounts.email(), :hotp) :: Secret.hotp_t()
  def create_secret_for_user(email, :hotp), do: Secret.new_totp(email)

  @doc """
  Returns the html string `<img />` tag with a src=data: uri containing the Google Authenticator-compatible enrollment QR code for the given secret

  If you need to attach this tag to styling on side of the fence, you can specify
  :id or a list of :classes as options
  """

  # TODO?: support data attributes?
  # TODO?: support width, height?
  # OR
  # TODO?:  support arbitrary key=value attributes

  # TODO?: return a phoenix-compatible
  #   {:safe, [IOList]}
  # instead of literal text. With or without help from a Phoenix.HTML.Tag dependency

  @spec enrollment_svg_img_element_for_secret(Secret.t(),
          classes: [String.t()],
          id: String.t() | nil
        ) :: String.t()
  def enrollment_svg_img_element_for_secret(%Secret{} = s, opts \\ []) do
    id = opts[:id] || nil
    classes = opts[:classes] || []

    img_tag = fn b64 ->
      el = [~s(<img src="data:image/svg+xml;base64,#{b64}")]
      el = if(is_nil(id), do: el, else: [~s(id="#{id}") | el])
      el = if(classes == [], do: el, else: [~s(class="#{Enum.join(classes, "")}") | el])
      el = ["/>" | el]

      el
      |> Enum.reverse()
      |> Enum.join(" ")
    end

    s
    |> enrollment_qr_code_base64_for_secret
    |> img_tag.()
  end

  @doc "Returns the raw SVG xml document for the Google Authenticator-compatible enrollment QR code for the given secret "
  @spec enrollment_svg_string_for_secret(Secret.t()) :: String.t()
  def enrollment_svg_string_for_secret(%Secret{} = s) do
    enrollment_qr_code_base64_for_secret(s)
    |> Base.decode64!()
  end

  defp enrollment_qr_code_base64_for_secret(%Secret{} = s) do
    s
    |> Secret.enrollment_url()
    |> QRCode.QR.create!()
    |> QRCode.Svg.to_base64()
  end


  @doc """
  Validate the Stein.MFA.OneTimePassword.Secret against user input

  Note for an HMAC-based secret you need to make sure the counter is right.
  If you are using `Secret.generate` (to e.g. pass to Twilio) just make sure
  you save its returned %Token{secret} to your data store for future use.
  """
  @spec validate_token(Secret.t(), Token.token_value()) :: boolean()
  def validate_token(%Secret{} = s, v), do: Token.validate(%Token{value: v, secret: s})
end
