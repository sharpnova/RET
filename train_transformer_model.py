import tensorflow as tf
import numpy as np

# Placeholder dataset
X_train = np.random.rand(1000, 8)
y_train = np.random.randint(0, 3, 1000)

model = tf.keras.Sequential([
    tf.keras.layers.Dense(128, activation='relu', input_shape=(8,)),
    tf.keras.layers.Dense(64, activation='relu'),
    tf.keras.layers.Dense(3, activation='softmax')
])

model.compile(optimizer='adam', loss='sparse_categorical_crossentropy', metrics=['accuracy'])
model.fit(X_train, y_train, epochs=10, batch_size=32)
model.save('transformer_model.h5')