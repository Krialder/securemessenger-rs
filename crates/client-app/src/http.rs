//! Gemeinsame HTTP-Helfer der Dienst-Clients: Transportfehler, das
//! einheitliche Fehlerformat (`code`, `message` nach schnittstellen.md) und
//! das Lesen von JSON-Antworten. Ein Modul statt Kopien je Client, damit
//! sich das Fehlerverhalten nicht auseinanderentwickelt.

use serde::de::DeserializeOwned;
use serde::Deserialize;

use crate::error::ClientError;

/// Das einheitliche Fehlerformat der Dienste.
#[derive(Deserialize)]
struct ApiErrorBody {
    code: String,
    message: String,
}

pub(crate) fn transport(error: reqwest::Error) -> ClientError {
    ClientError::Transport(error.to_string())
}

/// Liest eine erfolgreiche JSON-Antwort oder übersetzt einen Fehlerstatus in
/// einen `ClientError::Api`.
pub(crate) async fn parse_json<T: DeserializeOwned>(
    response: reqwest::Response,
) -> Result<T, ClientError> {
    let status = response.status();
    if status.is_success() {
        response
            .json::<T>()
            .await
            .map_err(|error| ClientError::Decode(error.to_string()))
    } else {
        Err(api_error(status.as_u16(), response).await)
    }
}

/// Wie `parse_json`, aber ohne Textkörper im Erfolgsfall (z. B. `204`).
pub(crate) async fn expect_success(response: reqwest::Response) -> Result<(), ClientError> {
    let status = response.status();
    if status.is_success() {
        Ok(())
    } else {
        Err(api_error(status.as_u16(), response).await)
    }
}

/// Baut aus einer Fehlerantwort einen `ClientError::Api`. Fehlt der
/// erwartete Textkörper, bleibt wenigstens der HTTP-Status erhalten.
async fn api_error(status: u16, response: reqwest::Response) -> ClientError {
    match response.json::<ApiErrorBody>().await {
        Ok(body) => ClientError::Api {
            status,
            code: body.code,
            message: body.message,
        },
        Err(_) => ClientError::Api {
            status,
            code: "unknown".to_string(),
            message: "Fehlerantwort ohne lesbaren Textkörper".to_string(),
        },
    }
}
