---
name: android-dev
description: Kotlin + Jetpack Compose, ViewModel, Room, Hilt DI, Android lifecycle
metadata:
  type: skill
  triggers: ["android", "kotlin", "jetpack compose", "viewmodel", "room database", "hilt"]
---

# Android Development (Kotlin + Compose)

## Project structure (MVVM)
```
data/repository/  data/local/  data/remote/
domain/model/  domain/usecase/
presentation/screen/  presentation/viewmodel/
```

## ViewModel + StateFlow
```kotlin
@HiltViewModel
class UserViewModel @Inject constructor(
    private val userRepo: UserRepository
) : ViewModel() {
    private val _uiState = MutableStateFlow<UiState>(UiState.Loading)
    val uiState: StateFlow<UiState> = _uiState.asStateFlow()

    fun loadUser(id: String) {
        viewModelScope.launch {
            userRepo.getUser(id)
                .onSuccess { _uiState.value = UiState.Success(it) }
                .onFailure { _uiState.value = UiState.Error(it.message) }
        }
    }
}
```

## Compose screen
```kotlin
@Composable
fun UserScreen(viewModel: UserViewModel = hiltViewModel()) {
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()
    when (uiState) {
        is UiState.Loading -> CircularProgressIndicator()
        is UiState.Success -> UserContent((uiState as UiState.Success).user)
        is UiState.Error -> Text("Error: ${(uiState as UiState.Error).message}")
    }
}
```

## Room
```kotlin
@Entity data class User(@PrimaryKey val id: String, val email: String)

@Dao interface UserDao {
    @Query("SELECT * FROM user WHERE id = :id") suspend fun getById(id: String): User?
    @Insert(onConflict = REPLACE) suspend fun insert(user: User)
}
```
